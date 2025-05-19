package wallets

func NewWallet(id string) *Wallet {
	return &Wallet{
		ID: id,
	}
}

type Wallet struct {
	ID      string
	balance float64
}

func (w *Wallet) Deposit(amount float64) {
	w.balance += amount
}

func (w *Wallet) Withdraw(amount float64) {
	w.balance -= amount
}

func (w *Wallet) GetBalance() float64 {
	return w.balance
}
