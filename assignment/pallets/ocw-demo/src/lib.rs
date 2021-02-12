//! A demonstration of an offchain worker that sends onchain callbacks

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod tests;

use core::{convert::TryInto, fmt};
use frame_support::{
	debug, decl_error, decl_event, decl_module, decl_storage, dispatch::DispatchResult,
};
use parity_scale_codec::{Decode, Encode};

use frame_system::{
	self as system, ensure_none, ensure_signed,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
		SignedPayload, SigningTypes, Signer, SubmitTransaction,
	},
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	RuntimeDebug,
	offchain as rt_offchain,
	offchain::{
		storage::StorageValueRef,
		storage_lock::{StorageLock, BlockAndTime},
	},
	transaction_validity::{
		InvalidTransaction, TransactionSource, TransactionValidity,
		ValidTransaction,
	},
};
use sp_std::{
	prelude::*, str,
	collections::vec_deque::VecDeque,
};

use lite_json::json::JsonValue;
use serde::{Deserialize, Deserializer};

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When an offchain worker is signing transactions it's going to request keys from type
/// `KeyTypeId` via the keystore to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"demo");
pub const NUM_VEC_LEN: usize = 10;
/// The type to sign and send transactions.
pub const UNSIGNED_TXS_PRIORITY: u64 = 100;

// We are fetching information from the github public API about organization`substrate-developer-hub`.
// "https://api.github.com/orgs/substrate-developer-hub";
pub const HTTP_REMOTE_REQUEST: &str =  "https://min-api.cryptocompare.com/data/price?fsym=DOT&tsyms=USD";
// pub const HTTP_HEADER_USER_AGENT: &str = "jimmychu0807";

pub const FETCH_TIMEOUT_PERIOD: u64 = 3000; // in milli-seconds
pub const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000; // in milli-seconds
pub const LOCK_BLOCK_EXPIRATION: u32 = 3; // in block number

pub const MAX_LEN: usize = 10;


/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// them with the pallet-specific identifier.
pub mod crypto {
	use crate::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{
		traits::Verify,
		MultiSignature, MultiSigner,
	};

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	// implemented for ocw-runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct Payload<Public> {
	number: u32,
	public: Public
}

impl <T: SigningTypes> SignedPayload<T> for Payload<T::Public> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

// ref: https://serde.rs/container-attrs.html#crate
#[derive(Deserialize, Encode, Decode, Default)]
struct GithubInfo {
	// Specify our own deserializing function to convert JSON string to vector of bytes
	#[serde(deserialize_with = "de_string_to_bytes")]
	login: Vec<u8>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	blog: Vec<u8>,
	public_repos: u32,
}

#[derive(Deserialize, Encode, Decode, Default)]
struct PricePayload {
	usd: u32, //price
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(de)?;
	Ok(s.as_bytes().to_vec())
}

impl fmt::Debug for GithubInfo {
	// `fmt` converts the vector of bytes inside the struct back to string for
	//   more friendly display.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"{{ login: {}, blog: {}, public_repos: {} }}",
			str::from_utf8(&self.login).map_err(|_| fmt::Error)?,
			str::from_utf8(&self.blog).map_err(|_| fmt::Error)?,
			&self.public_repos
		)
	}
}

/// This is the pallet's configuration trait
pub trait Trait: system::Trait + CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
	trait Store for Module<T: Trait> as Example {
		/// A vector of recently submitted numbers. Bounded by NUM_VEC_LEN
		Numbers get(fn numbers): VecDeque<u32>;

		/// A vector of recently submitted prices. Should have bounded size of 10.
		Prices get(fn prices): Vec<u32>;
	}
}

decl_event!(
	/// Events generated by the module.
	pub enum Event<T>
	where
		AccountId = <T as system::Trait>::AccountId,
	{
		/// Event generated when a new number is accepted to contribute to the average.
		NewNumber(Option<AccountId>, u32),
		NewPrice(u32, AccountId),
	}
);

decl_error! {
	pub enum Error for Module<T: Trait> {
		// Error returned when not sure which ocw function to executed
		UnknownOffchainMux,

		// Error returned when making signed transactions in off-chain worker
		NoLocalAcctForSigning,
		OffchainSignedTxError,

		// Error returned when making unsigned transactions in off-chain worker
		OffchainUnsignedTxError,

		// Error returned when making unsigned transactions with signed payloads in off-chain worker
		OffchainUnsignedTxSignedPayloadError,

		// Error returned when fetching github info
		HttpFetchingError,
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		// #[weight = 10000]
		// pub fn submit_number_signed(origin, number: u32) -> DispatchResult {
		// 	let who = ensure_signed(origin)?;
		// 	debug::info!("🐂🍺 submit_number_signed: ({}, {:?})", number, who);
		// 	Self::append_or_replace_number(number);

		// 	Self::deposit_event(RawEvent::NewNumber(Some(who), number));
		// 	Ok(())
		// }

		// #[weight = 10000]
		// pub fn submit_number_unsigned(origin, number: u32) -> DispatchResult {
		// 	let _ = ensure_none(origin)?;
		// 	debug::info!("🐂🍺 submit_number_unsigned: {}", number);
		// 	Self::append_or_replace_number(number);

		// 	Self::deposit_event(RawEvent::NewNumber(None, number));
		// 	Ok(())
		// }

		// #[weight = 10000]
		// pub fn submit_number_unsigned_with_signed_payload(origin, payload: Payload<T::Public>,
		// 	_signature: T::Signature) -> DispatchResult
		// {
		// 	let _ = ensure_none(origin)?;
		// 	// we don't need to verify the signature here because it has been verified in
		// 	//   `validate_unsigned` function when sending out the unsigned tx.
		// 	let Payload { number, public } = payload;
		// 	debug::info!("🐂🍺 submit_number_unsigned_with_signed_payload: ({}, {:?})", number, public);
		// 	Self::append_or_replace_number(number);

		// 	Self::deposit_event(RawEvent::NewNumber(None, number));
		// 	Ok(())
		// }

		#[weight = 0]
		pub fn submit_price(origin, price: u32) -> DispatchResult {
			// Retrieve sender of the transaction.
			let who = ensure_signed(origin)?;
			// Add the price to the on-chain list.
			Self::add_price(who, price);
			Ok(())
		}

		fn offchain_worker(block_number: T::BlockNumber) {
			debug::info!("🐂🍺 Entering off-chain worker...");

			// Here we are showcasing various techniques used when running off-chain workers (ocw)
			// 1. Sending signed transaction from ocw
			// 2. Sending unsigned transaction from ocw
			// 3. Sending unsigned transactions with signed payloads from ocw
			// 4. Fetching JSON via http requests in ocw
			// const TX_TYPES: u32 = 4;
			// let modu = block_number.try_into().map_or(TX_TYPES, |bn: u32| bn % TX_TYPES);
			// let result = match modu {
			// 	0 => Self::fetch_price_and_send_signed(),
			// 	1 => Self::fetch_price_and_send_signed(),
			// 	2 => Self::fetch_price_and_send_signed(),
			// 	3 => Self::fetch_price_and_send_signed(),
			// 	// 0 => Self::offchain_signed_tx(block_number),
			// 	// 1 => Self::offchain_unsigned_tx(block_number),
			// 	// 2 => Self::offchain_unsigned_tx_signed_payload(block_number),
			// 	// 3 => Self::fetch_github_info(),
			// 	// _ => Err(Error::<T>::UnknownOffchainMux),
			// 	_ => Ok(()),
			// };

			let result = Self::fetch_price_and_send_signed();

			if let Err(e) = result {
				debug::error!("🐂🍺 offchain_worker error: {:?}", e);
			}
		}
	}
}

impl<T: Trait> Module<T> {

	// 使用signed模式可能更好，因为交易是有签名的，知道这个链外数据是谁发布的，能起到溯源的效果。
	fn fetch_price_and_send_signed() -> Result<(), &'static str> {
		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC."
			)?
		}
		let price = Self::fetch_n_parse().map_err(|err| { debug::warn!("🐂🍺 fetch price error: {:?}", err); "Failed to fetch price{}"})?;
		let _ = Self::cache_price_info(price).map_err(|err| { debug::warn!("🐂🍺 cache price error: {:?}", err); "Failed to cache price{}"})?;

		let results = signer.send_signed_transaction(
			|_account| {
				Call::submit_price(price)
			}
		);

		for (acc, res) in &results {
			match res {
				Ok(()) => debug::info!("🐂🍺 [{:?}] Submitted price of {} DOT/USDT", acc.id, (price as f32)/100_f32),
				Err(e) => debug::error!("🐂🍺 [{:?}] Failed to submit transaction: {:?}", acc.id, e),
			}
		}
		Ok(())
	}

	/// Fetch current price and return the result in cents.
	fn fetch_n_parse() -> Result<u32, rt_offchain::http::Error> {
		let deadline = sp_io::offchain::timestamp().add(rt_offchain::Duration::from_millis(FETCH_TIMEOUT_PERIOD));
		let request = rt_offchain::http::Request::get(
			HTTP_REMOTE_REQUEST
		);
		let pending = request
			.deadline(deadline)
			.send()
			.map_err(|_| rt_offchain::http::Error::IoError)?;

		let response = pending.try_wait(deadline)
			.map_err(|_| rt_offchain::http::Error::DeadlineReached)??;
		if response.code != 200 {
			debug::warn!("🐂🍺 Unexpected status code: {}", response.code);
			return Err(rt_offchain::http::Error::Unknown);
		}

		let body = response.body().collect::<Vec<u8>>();

		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			debug::warn!("🐂🍺 No UTF8 body");
			rt_offchain::http::Error::Unknown
		})?;

		let price = match Self::parse_price(body_str) {
			Some(price) => Ok(price),
			None => {
				debug::warn!("🐂🍺 Unable to extract price from the response: {:?}", body_str);
				Err(rt_offchain::http::Error::Unknown)
			}
		}?;

		debug::info!("🐂🍺 Got price of DOT/USDT: {} ", (price as f32)/100_f32);

		Ok(price)
	}

	/// Parse the price from the given JSON string using `lite-json`.
	///
	/// Returns `None` when parsing failed or `Some(price in cents)` when parsing is successful.
	fn parse_price(price_str: &str) -> Option<u32> {
		let val = lite_json::parse_json(price_str);
		let price = val.ok().and_then(|v| match v {
			JsonValue::Object(obj) => {
				let mut chars = "USD".chars();
				obj.into_iter()
					.find(|(k, _)| k.iter().all(|k| Some(*k) == chars.next()))
					.and_then(|v| match v.1 {
						JsonValue::Number(number) => Some(number),
						_ => None,
					})
			},
			_ => None
		})?;
		debug::info!("🐻🍺 fraction: {}, fraction_length: {}, ", price.fraction, price.fraction_length);
		let exp = price.fraction_length.checked_sub(2).unwrap_or(0);
		Some(price.integer as u32 * 100 + (price.fraction / 10_u64.pow(exp)) as u32)
	}

	// fn parse_price2(price_str: &str) -> Result<f32, Error<T>> {
	// 	let price_payload: PricePayload =
	// 	serde_json::from_str(&price_str).map_err(|_| <Error<T>>::HttpFetchingError)?;
	// 	Ok(price_payload.usd)
	// }

	/// Fetch from remote and deserialize the JSON to a struct
	// fn fetch_n_parse() -> Result<GithubInfo, Error<T>> {
	// 	let resp_bytes = Self::fetch_from_remote().map_err(|e| {
	// 		debug::error!("fetch_from_remote error: {:?}", e);
	// 		<Error<T>>::HttpFetchingError
	// 	})?;

	// 	let resp_str = str::from_utf8(&resp_bytes).map_err(|_| <Error<T>>::HttpFetchingError)?;
	// 	// Print out our fetched JSON string
	// 	debug::info!("{}", resp_str);

	// 	// Deserializing JSON to struct, thanks to `serde` and `serde_derive`
	// 	let gh_info: GithubInfo =
	// 		serde_json::from_str(&resp_str).map_err(|_| <Error<T>>::HttpFetchingError)?;
	// 	Ok(gh_info)
	// }

	/// Add new price to the list.
	fn add_price(who: T::AccountId, price: u32) {
		let mut len = 0;
		debug::info!("🐂🍺 Adding to vector with new price: {}", (price as f32)/100_f32);
		Prices::mutate(|prices| {
			// const MAX_LEN: usize = 10;
			len = prices.len();
			if prices.len() < MAX_LEN {
				prices.push(price);
			} else {
				prices.remove(0);
				prices.push(price);
				// prices[price as usize % MAX_LEN] = price;
			}
		});

		// let average = Self::average_price()
			// .expect("The average is not empty, because it was just mutated; qed");
		// debug::info!("🐂🍺 Current price vec is: {}",);
		Self::show_all_price();
		debug::info!("🐂🍺 Current price.len is: {}", len);
		// debug::info!("🐂🍺 Current average price is: {}", (average as f32)/100_f32);
		// here we are raising the NewPrice event
		Self::deposit_event(RawEvent::NewPrice(price, who));
	}

	/// Calculate current average price.
	// fn average_price() -> Option<u32> {
	// 	let prices = Prices::get();
	// 	if prices.is_empty() {
	// 		None
	// 	} else {
	// 		Some(prices.iter().fold(0_u32, |a, b| a.saturating_add(*b)) / prices.len() as u32)
	// 	}
	// }

	fn show_all_price() {
		let prices = Prices::get();
		if prices.is_empty() {
			debug::info!("🐂🍺 Price vector: empty");
		} else {
			debug::info!("🐂🍺 Price vector: [");
			prices.iter().fold(0_u32, |a, b| {debug::info!("🐂🍺 {}", (*b as f32)/100_f32);*b});
			debug::info!("🐂🍺 ]");
		}
	}


	// /// Append a new number to the tail of the list, removing an element from 	
	// /// the head if reaching
	// ///   the bounded length.
	// fn append_or_replace_number(number: u32) {
	// 	Numbers::mutate(|numbers| {
	// 		if numbers.len() == NUM_VEC_LEN {
	// 			let _ = numbers.pop_front();
	// 		}
	// 		numbers.push_back(number);
	// 		debug::info!("Number vector: {:?}", numbers);
	// 	});
	// }

	/// Check if we have fetched github info before. If yes, we can use the cached version
	///   stored in off-chain worker storage `storage`. If not, we fetch the remote info and
	///   write the info into the storage for future retrieval.
	fn cache_price_info(price: u32) -> Result<(), Error<T>> {
		let s_info = StorageValueRef::persistent(b"offchain-demo::dot-price");

		// Local storage is persisted and shared between runs of the offchain workers,
		// offchain workers may run concurrently. We can use the `mutate` function to
		// write a storage entry in an atomic fashion.
		//
		// With a similar API as `StorageValue` with the variables `get`, `set`, `mutate`.
		// We will likely want to use `mutate` to access
		// the storage comprehensively.
		//
		// Ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/storage/struct.StorageValueRef.html
		// if let Some(Some(price_info)) = s_info.get::<u32>() {
		// 	// dot-price has already been fetched. Return early.
		// 	debug::info!("🐂🍺 Get cached DOT/USDT price: {}", price_info);
		// 	return Ok(());
		// };

		// Since off-chain storage can be accessed by off-chain workers from multiple runs, it is important to lock
		//   it before doing heavy computations or write operations.
		// ref: https://substrate.dev/rustdocs/v2.0.0-rc3/sp_runtime/offchain/storage_lock/index.html
		//
		// There are four ways of defining a lock:
		//   1) `new` - lock with default time and block exipration
		//   2) `with_deadline` - lock with default block but custom time expiration
		//   3) `with_block_deadline` - lock with default time but custom block expiration
		//   4) `with_block_and_time_deadline` - lock with custom time and block expiration
		// Here we choose the most custom one for demonstration purpose.
		let mut lock = StorageLock::<BlockAndTime<Self>>::with_block_and_time_deadline(
			b"offchain-demo::lock", LOCK_BLOCK_EXPIRATION,
			rt_offchain::Duration::from_millis(LOCK_TIMEOUT_EXPIRATION)
		);

		// We try to acquire the lock here. If failed, we know the `fetch_n_parse` part inside is being
		//   executed by previous run of ocw, so the function just returns.
		// ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/storage_lock/struct.StorageLock.html#method.try_lock
		if let Ok(_guard) = lock.try_lock() {
			s_info.set(&price); 
			debug::info!("🐂🍺 Cache DOT/USDT price locally success: {}", (price as f32)/100_f32 );
			// match Self::fetch_n_parse() {
			// 	Ok(price) => { s_info.set(&price); debug::info!("cache dot-price: {}", price); }
			// 	Err(err) => { return Err(<Error<T>>::HttpFetchingError); }
			// }
		}
		Ok(())
	}


	// /// Check if we have fetched github info before. If yes, we can use the cached version
	// ///   stored in off-chain worker storage `storage`. If not, we fetch the remote info and
	// ///   write the info into the storage for future retrieval.
	// fn fetch_github_info() -> Result<(), Error<T>> {
	// 	// Create a reference to Local Storage value.
	// 	// Since the local storage is common for all offchain workers, it's a good practice
	// 	// to prepend our entry with the pallet name.
	// 	let s_info = StorageValueRef::persistent(b"offchain-demo::dot-price");

	// 	// Local storage is persisted and shared between runs of the offchain workers,
	// 	// offchain workers may run concurrently. We can use the `mutate` function to
	// 	// write a storage entry in an atomic fashion.
	// 	//
	// 	// With a similar API as `StorageValue` with the variables `get`, `set`, `mutate`.
	// 	// We will likely want to use `mutate` to access
	// 	// the storage comprehensively.
	// 	//
	// 	// Ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/storage/struct.StorageValueRef.html
	// 	if let Some(Some(gh_info)) = s_info.get::<GithubInfo>() {
	// 		// dot-price has already been fetched. Return early.
	// 		debug::info!("cached dot-price: {:?}", gh_info);
	// 		return Ok(());
	// 	}

	// 	// Since off-chain storage can be accessed by off-chain workers from multiple runs, it is important to lock
	// 	//   it before doing heavy computations or write operations.
	// 	// ref: https://substrate.dev/rustdocs/v2.0.0-rc3/sp_runtime/offchain/storage_lock/index.html
	// 	//
	// 	// There are four ways of defining a lock:
	// 	//   1) `new` - lock with default time and block exipration
	// 	//   2) `with_deadline` - lock with default block but custom time expiration
	// 	//   3) `with_block_deadline` - lock with default time but custom block expiration
	// 	//   4) `with_block_and_time_deadline` - lock with custom time and block expiration
	// 	// Here we choose the most custom one for demonstration purpose.
	// 	let mut lock = StorageLock::<BlockAndTime<Self>>::with_block_and_time_deadline(
	// 		b"offchain-demo::lock", LOCK_BLOCK_EXPIRATION,
	// 		rt_offchain::Duration::from_millis(LOCK_TIMEOUT_EXPIRATION)
	// 	);

	// 	// We try to acquire the lock here. If failed, we know the `fetch_n_parse` part inside is being
	// 	//   executed by previous run of ocw, so the function just returns.
	// 	// ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/storage_lock/struct.StorageLock.html#method.try_lock
	// 	if let Ok(_guard) = lock.try_lock() {
	// 		match Self::fetch_n_parse() {
	// 			Ok(gh_info) => { s_info.set(&gh_info); }
	// 			Err(err) => { return Err(err); }
	// 		}
	// 	}
	// 	Ok(())
	// }

	// /// Fetch from remote and deserialize the JSON to a struct
	// fn fetch_n_parse() -> Result<GithubInfo, Error<T>> {
	// 	let resp_bytes = Self::fetch_from_remote().map_err(|e| {
	// 		debug::error!("fetch_from_remote error: {:?}", e);
	// 		<Error<T>>::HttpFetchingError
	// 	})?;

	// 	let resp_str = str::from_utf8(&resp_bytes).map_err(|_| <Error<T>>::HttpFetchingError)?;
	// 	// Print out our fetched JSON string
	// 	debug::info!("{}", resp_str);

	// 	// Deserializing JSON to struct, thanks to `serde` and `serde_derive`
	// 	let gh_info: GithubInfo =
	// 		serde_json::from_str(&resp_str).map_err(|_| <Error<T>>::HttpFetchingError)?;
	// 	Ok(gh_info)
	// }

	// /// This function uses the `offchain::http` API to query the remote github information,
	// ///   and returns the JSON response as vector of bytes.
	// fn fetch_from_remote() -> Result<Vec<u8>, Error<T>> {
	// 	debug::info!("sending request to: {}", HTTP_REMOTE_REQUEST);

	// 	// Initiate an external HTTP GET request. This is using high-level wrappers from `sp_runtime`.
	// 	let request = rt_offchain::http::Request::get(HTTP_REMOTE_REQUEST);

	// 	// Keeping the offchain worker execution time reasonable, so limiting the call to be within 3s.
	// 	let timeout = sp_io::offchain::timestamp()
	// 		.add(rt_offchain::Duration::from_millis(FETCH_TIMEOUT_PERIOD));

	// 	// For github API request, we also need to specify `user-agent` in http request header.
	// 	//   See: https://developer.github.com/v3/#user-agent-required
	// 	let pending = request
	// 		.add_header("User-Agent", HTTP_HEADER_USER_AGENT)
	// 		.deadline(timeout) // Setting the timeout time
	// 		.send() // Sending the request out by the host
	// 		.map_err(|_| <Error<T>>::HttpFetchingError)?;

	// 	// By default, the http request is async from the runtime perspective. So we are asking the
	// 	//   runtime to wait here.
	// 	// The returning value here is a `Result` of `Result`, so we are unwrapping it twice by two `?`
	// 	//   ref: https://substrate.dev/rustdocs/v2.0.0/sp_runtime/offchain/http/struct.PendingRequest.html#method.try_wait
	// 	let response = pending
	// 		.try_wait(timeout)
	// 		.map_err(|_| <Error<T>>::HttpFetchingError)?
	// 		.map_err(|_| <Error<T>>::HttpFetchingError)?;

	// 	if response.code != 200 {
	// 		debug::error!("Unexpected http request status code: {}", response.code);
	// 		return Err(<Error<T>>::HttpFetchingError);
	// 	}

	// 	// Next we fully read the response body and collect it to a vector of bytes.
	// 	Ok(response.body().collect::<Vec<u8>>())
	// }

	// fn offchain_signed_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
	// 	// We retrieve a signer and check if it is valid.
	// 	//   Since this pallet only has one key in the keystore. We use `any_account()1 to
	// 	//   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
	// 	//   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.Signer.html
	// 	let signer = Signer::<T, T::AuthorityId>::any_account();

	// 	// Translating the current block number to number and submit it on-chain
	// 	let number: u32 = block_number.try_into().unwrap_or(0);

	// 	// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
	// 	//   - `None`: no account is available for sending transaction
	// 	//   - `Some((account, Ok(())))`: transaction is successfully sent
	// 	//   - `Some((account, Err(())))`: error occured when sending the transaction
	// 	let result = signer.send_signed_transaction(|_acct|
	// 		// This is the on-chain function
	// 		Call::submit_number_signed(number)
	// 	);

	// 	// Display error if the signed tx fails.
	// 	if let Some((acc, res)) = result {
	// 		if res.is_err() {
	// 			debug::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
	// 			return Err(<Error<T>>::OffchainSignedTxError);
	// 		}
	// 		// Transaction is sent successfully
	// 		return Ok(());
	// 	}

	// 	// The case of `None`: no account is available for sending
	// 	debug::error!("No local account available");
	// 	Err(<Error<T>>::NoLocalAcctForSigning)
	// }

	// fn offchain_unsigned_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
	// 	let number: u32 = block_number.try_into().unwrap_or(0);
	// 	let call = Call::submit_number_unsigned(number);

	// 	// `submit_unsigned_transaction` returns a type of `Result<(), ()>`
	// 	//   ref: https://substrate.dev/rustdocs/v2.0.0/frame_system/offchain/struct.SubmitTransaction.html#method.submit_unsigned_transaction
	// 	SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
	// 		.map_err(|_| {
	// 			debug::error!("Failed in offchain_unsigned_tx");
	// 			<Error<T>>::OffchainUnsignedTxError
	// 		})
	// }

	// fn offchain_unsigned_tx_signed_payload(block_number: T::BlockNumber) -> Result<(), Error<T>> {
	// 	// Retrieve the signer to sign the payload
	// 	let signer = Signer::<T, T::AuthorityId>::any_account();

	// 	let number: u32 = block_number.try_into().unwrap_or(0);

	// 	// `send_unsigned_transaction` is returning a type of `Option<(Account<T>, Result<(), ()>)>`.
	// 	//   Similar to `send_signed_transaction`, they account for:
	// 	//   - `None`: no account is available for sending transaction
	// 	//   - `Some((account, Ok(())))`: transaction is successfully sent
	// 	//   - `Some((account, Err(())))`: error occured when sending the transaction
	// 	if let Some((_, res)) = signer.send_unsigned_transaction(
	// 		|acct| Payload { number, public: acct.public.clone() },
	// 		Call::submit_number_unsigned_with_signed_payload
	// 	) {
	// 		return res.map_err(|_| {
	// 			debug::error!("Failed in offchain_unsigned_tx_signed_payload");
	// 			<Error<T>>::OffchainUnsignedTxSignedPayloadError
	// 		});
	// 	}

	// 	// The case of `None`: no account is available for sending
	// 	debug::error!("No local account available");
	// 	Err(<Error<T>>::NoLocalAcctForSigning)
	// }
}

// impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
	// type Call = Call<T>;

	// fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
	// 	let valid_tx = |provide| ValidTransaction::with_tag_prefix("ocw-demo")
	// 		.priority(UNSIGNED_TXS_PRIORITY)
	// 		.and_provides([&provide])
	// 		.longevity(3)
	// 		.propagate(true)
	// 		.build();

	// 	match call {
	// 		Call::submit_number_unsigned(_number) => valid_tx(b"submit_number_unsigned".to_vec()),
	// 		Call::submit_number_unsigned_with_signed_payload(ref payload, ref signature) => {
	// 			if !SignedPayload::<T>::verify::<T::AuthorityId>(payload, signature.clone()) {
	// 				return InvalidTransaction::BadProof.into();
	// 			}
	// 			valid_tx(b"submit_number_unsigned_with_signed_payload".to_vec())
	// 		},
	// 		_ => InvalidTransaction::Call.into(),
	// 	}
	// }
// }

impl<T: Trait> rt_offchain::storage_lock::BlockNumberProvider for Module<T> {
	type BlockNumber = T::BlockNumber;
	fn current_block_number() -> Self::BlockNumber {
	  <frame_system::Module<T>>::block_number()
	}
}
