use bitcoin::Amount;
use bitcoin::SignedAmount;
use bitcoin::Txid;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ArkTransaction {
    /// A transaction that transforms a UTXO into a boarding output.
    Boarding {
        txid: Txid,
        /// We use [`Amount`] because boarding transactions are always incoming i.e. we receive a
        /// boarding output.
        amount: Amount,
        confirmed_at: Option<i64>,
    },
    /// A transaction that confirms VTXOs.
    Commitment {
        txid: Txid,
        /// We use [`SignedAmount`] because commitment transactions may be incoming or outgoing
        /// i.e. we can send or receive VTXOs.
        amount: SignedAmount,
        created_at: i64,
    },
    /// A transaction that sends VTXOs.
    Virtual {
        txid: Txid,
        /// We use [`SignedAmount`] because virtual transactions may be incoming or outgoing i.e.
        /// we can send or receive VTXOs.
        amount: SignedAmount,
        /// A redeem transaction is settled if our outputs in it have been spent.
        is_settled: bool,
        created_at: i64,
    },
}

impl ArkTransaction {
    /// The creation time of the [`ArkTransaction`]. This value can be used for sorting.
    ///
    /// - The creation time of a boarding transaction is based on its confirmation time. If it is
    ///   pending, we return [`None`].
    ///
    /// - The creation time of a commitment transaction is based on the `created_at` of our VTXO
    ///   produced by it.
    ///
    /// - The creation time of a virtual transaction is based on the `created_at` of our VTXO
    ///   produced by it.
    pub fn created_at(&self) -> Option<i64> {
        match self {
            ArkTransaction::Boarding { confirmed_at, .. } => *confirmed_at,
            ArkTransaction::Commitment { created_at, .. }
            | ArkTransaction::Virtual { created_at, .. } => Some(*created_at),
        }
    }

    pub fn txid(&self) -> Txid {
        match self {
            ArkTransaction::Boarding { txid, .. }
            | ArkTransaction::Commitment { txid, .. }
            | ArkTransaction::Virtual { txid, .. } => *txid,
        }
    }
}

/// Sorts a slice of [`ArkTransaction`] in descending order by creation time.
///
/// Transactions with no creation time (None) are placed first, followed by transactions
/// sorted by creation time in descending order (newest first).
pub fn sort_transactions_by_created_at(txs: &mut [ArkTransaction]) {
    txs.sort_by(|a, b| match (a.created_at(), b.created_at()) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(a_time), Some(b_time)) => b_time.cmp(&a_time),
    });
}
