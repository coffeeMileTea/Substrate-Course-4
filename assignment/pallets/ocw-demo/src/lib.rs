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
		AppCrypto, CreateSignedTransaction, SendSignedTransaction,
		SignedPayload, SigningTypes, Signer,
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

	fn cache_price_info(price: u32) -> Result<(), Error<T>> {
		let s_info = StorageValueRef::persistent(b"offchain-demo::dot-price");

		let mut lock = StorageLock::<BlockAndTime<Self>>::with_block_and_time_deadline(
			b"offchain-demo::lock", LOCK_BLOCK_EXPIRATION,
			rt_offchain::Duration::from_millis(LOCK_TIMEOUT_EXPIRATION)
		);

		if let Ok(_guard) = lock.try_lock() {
			s_info.set(&price); 
			debug::info!("🐂🍺 Cache DOT/USDT price locally success: {}", (price as f32)/100_f32 );
		}
		Ok(())
	}
}


impl<T: Trait> rt_offchain::storage_lock::BlockNumberProvider for Module<T> {
	type BlockNumber = T::BlockNumber;
	fn current_block_number() -> Self::BlockNumber {
	  <frame_system::Module<T>>::block_number()
	}
}
