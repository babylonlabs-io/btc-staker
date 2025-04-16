package babylonclient

import (
	"context"
	"errors"
	"fmt"
	"sync"

	bct "github.com/babylonlabs-io/babylon/client/babylonclient"
	"golang.org/x/sync/semaphore"

	"github.com/babylonlabs-io/btc-staker/utils"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/sirupsen/logrus"
)

var (
	ErrBabylonBtcLightClientNotReady = errors.New("babylon btc light client is not ready to receive delegation")
)

type sendDelegationRequest struct {
	utils.Request[*bct.RelayerTxResponse]
	dg                          *DelegationData
	requiredInclusionBlockDepth uint32
}

func newSendDelegationRequest(
	dg *DelegationData,
	requiredInclusionBlockDepth uint32,
) sendDelegationRequest {
	return sendDelegationRequest{
		Request:                     utils.NewRequest[*bct.RelayerTxResponse](),
		dg:                          dg,
		requiredInclusionBlockDepth: requiredInclusionBlockDepth,
	}
}

// BabylonMsgSender is responsible for sending delegation and undelegation requests to babylon
// It makes sure:
// - that babylon is ready for either delgetion or undelegation
// - only one messegae is sent to babylon at a time
type BabylonMsgSender struct {
	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
	quit      chan struct{}

	cl                        BabylonClient
	logger                    *logrus.Logger
	sendDelegationRequestChan chan *sendDelegationRequest
	s                         *semaphore.Weighted
}

func NewBabylonMsgSender(
	cl BabylonClient,
	logger *logrus.Logger,
	maxConcurrentTransactions uint32,
) *BabylonMsgSender {
	s := semaphore.NewWeighted(int64(maxConcurrentTransactions))
	return &BabylonMsgSender{
		quit:                      make(chan struct{}),
		cl:                        cl,
		logger:                    logger,
		sendDelegationRequestChan: make(chan *sendDelegationRequest),
		s:                         s,
	}
}

func (m *BabylonMsgSender) Start() {
	m.startOnce.Do(func() {
		m.wg.Add(1)
		go m.handleSentToBabylon()
	})
}

func (m *BabylonMsgSender) Stop() {
	m.stopOnce.Do(func() {
		close(m.quit)
		m.wg.Wait()
	})
}

// isBabylonBtcLcReady checks if Babylon BTC light client is ready to receive delegation
func (m *BabylonMsgSender) isBabylonBtcLcReady(
	requiredInclusionBlockDepth uint32,
	req *DelegationData,
) error {
	// no need to consult Babylon if we send delegation without inclusion proof
	if req.StakingTransactionInclusionInfo == nil {
		return nil
	}

	depth, err := m.cl.QueryHeaderDepth(req.StakingTransactionInclusionInfo.StakingTransactionInclusionBlockHash)

	if err != nil {
		// If header is not known to babylon, or it is on LCFork, then most probably
		// lc is not up to date. We should retry sending delegation after some time.
		if errors.Is(err, ErrHeaderNotKnownToBabylon) || errors.Is(err, ErrHeaderOnBabylonLCFork) {
			return fmt.Errorf("btc light client error %s: %w", err.Error(), ErrBabylonBtcLightClientNotReady)
		}

		// got some unknown error, return it to the caller
		return fmt.Errorf("error while getting delegation data: %w", err)
	}

	if depth < requiredInclusionBlockDepth {
		return fmt.Errorf("btc lc not ready, required depth: %d, current depth: %d: %w", requiredInclusionBlockDepth, depth, ErrBabylonBtcLightClientNotReady)
	}

	return nil
}

func (m *BabylonMsgSender) sendDelegationAsync(stakingTxHash *chainhash.Hash, req *sendDelegationRequest) {
	// do not check the error, as only way for it to return err is if provided context would be cancelled
	// which can't happen here
	_ = m.s.Acquire(context.Background(), 1)
	m.wg.Add(1)
	go func() {
		defer m.s.Release(1)
		defer m.wg.Done()
		// TODO pass context to delegate
		txResp, err := m.cl.Delegate(req.dg)

		if err != nil {
			if errors.Is(err, ErrInvalidBabylonExecution) {
				m.logger.WithFields(logrus.Fields{
					"btcTxHash":          stakingTxHash,
					"babylonTxHash":      txResp.TxHash,
					"babylonBlockHeight": txResp.Height,
					"babylonErrorCode":   txResp.Code,
				}).Error("Invalid delegation data sent to babylon")
			}

			m.logger.WithFields(logrus.Fields{
				"btcTxHash": stakingTxHash,
				"err":       err,
			}).Error("Error while sending delegation data to babylon")

			req.ErrorChan() <- fmt.Errorf("failed to send delegation for tx with hash: %s: %w", stakingTxHash.String(), err)
		}
		req.ResultChan() <- txResp
	}()
}

func (m *BabylonMsgSender) handleSentToBabylon() {
	defer m.wg.Done()
	for {
		select {
		case req := <-m.sendDelegationRequestChan:
			stakingTxHash := req.dg.StakingTransaction.TxHash()

			err := m.isBabylonBtcLcReady(
				req.requiredInclusionBlockDepth,
				req.dg,
			)

			if err != nil {
				m.logger.WithFields(logrus.Fields{
					"btcTxHash": stakingTxHash,
					"err":       err,
				}).Error("Cannot send delegation request to babylon")

				req.ErrorChan() <- err
				continue
			}

			m.sendDelegationAsync(&stakingTxHash, req)

		case <-m.quit:
			return
		}
	}
}

func (m *BabylonMsgSender) SendDelegation(
	dg *DelegationData,
	requiredInclusionBlockDepth uint32,
) (*bct.RelayerTxResponse, error) {
	req := newSendDelegationRequest(dg, requiredInclusionBlockDepth)

	return utils.SendRequestAndWaitForResponseOrQuit[*bct.RelayerTxResponse, *sendDelegationRequest](
		&req,
		m.sendDelegationRequestChan,
		m.quit,
	)
}
