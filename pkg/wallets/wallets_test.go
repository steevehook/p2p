package wallets

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type walletsSuite struct {
	suite.Suite
	wallet *Wallet
}

func (s *walletsSuite) SetupTest() {
	s.wallet = &Wallet{
		ID: "12345",
	}
}

func (s *walletsSuite) Test_NewWallet() {
	wallet := NewWallet("12345")

	s.Equal("12345", wallet.ID)
	s.Equal(0.0, wallet.balance)
}

func (s *walletsSuite) Test_Deposit() {
	s.wallet.Deposit(100.0)

	s.Equal(100.0, s.wallet.balance)
}

func (s *walletsSuite) Test_Withdraw() {
	s.wallet.balance = 100.0

	s.wallet.Withdraw(50.0)

	s.Equal(50.0, s.wallet.balance)
}

func (s *walletsSuite) Test_GetBalance() {
	s.wallet.balance = 100.0

	balance := s.wallet.GetBalance()

	s.Equal(100.0, balance)
}

func TestWallets(t *testing.T) {
	suite.Run(t, new(walletsSuite))
}
