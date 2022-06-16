package edu.usc.infolab.kien;

import edu.usc.infolab.kien.blockchaingeospatial.contract.generated.PrivGeoMarkt;
import edu.usc.infolab.kien.blockchaingeospatial.contract.generated.PrivGeoMarktCommitmentStorage;
import edu.usc.infolab.kien.blockchaingeospatial.contract.generated.PrivGeoMarktSearchableStorage;
import edu.usc.infolab.kien.blockchaingeospatial.eth.*;
import edu.usc.infolab.kien.blockchaingeospatial.storage.offer.OfferStatus;
import edu.usc.infolab.kien.blockchaingeospatial.utils.Utils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tuples.generated.Tuple2;
import org.web3j.tuples.generated.Tuple3;
import org.web3j.tuples.generated.Tuple6;
import org.web3j.tx.Contract;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.utils.Convert;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class PrivGeoMarktTest {
    private static Web3j web3j;

    private static ContractGasProvider contractGasProvider;

    private static ContractHelper privGeoMarktHelper;
    private static ContractHelper privGeoMarktCommitmentStorageHelper;
    private static ContractHelper privGeoMarktSearchableStorageHelper;

    private static final double OWNER_MIN_PRICE = 2.3;
    private static final String DATA_ADDRESS = "asasdjkfhasjkdfhaslkdfhaksdjfhaj";
    private static final String COMMITMENT = "asasdjkfhasjkdfhaslkdfhaksdjfhajskdfhaslkjdfhasdlflwieriweyruiwe";

    private static final String INDEX_ADDRESS = "kt86jtkgitjgutkyigjtuyktigktjt43";
    private static final long START_TIME = 1539800045;
    private static final long END_TIME = 1539886446;

    private static final long OFFER_EXPIRATION = 86400 * 3; //3 day
    private static final long REFUND_EXPIRATION = 86400 * 7; //7 days

    private static final String ENCRYPTED_KEYS = "6383045823784957204973150934578914358915678417645781647582647584";
    private static final int NUM_ENCRYPTED_KEYS = 1;

    @BeforeClass
    public static void prepare() {
        try {
            web3j = EthHelper.getWeb3jConnection();

            contractGasProvider = new DefaultGasProvider();

            privGeoMarktHelper = new PrivGeoMarktHelper(
                web3j,
                PrivGeoMarktHelper.DEFAULT_CONTRACT_ADDRESS,
                contractGasProvider);

            privGeoMarktCommitmentStorageHelper = new PrivGeoMarktCommitmentStorageHelper(
                web3j,
                PrivGeoMarktCommitmentStorageHelper.DEFAULT_CONTRACT_ADDRESS,
                contractGasProvider);

            privGeoMarktSearchableStorageHelper = new PrivGeoMarktSearchableStorageHelper(
                web3j,
                PrivGeoMarktSearchableStorageHelper.DEFAULT_CONTRACT_ADDRESS,
                contractGasProvider);


        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Before
    public void testContractValidity() {
        Assert.assertTrue("PrivGeoMarkt contracts are not valid",privGeoMarktHelper.isValid());
        Assert.assertTrue("PrivGeoMarktCommitmentStorage contracts are not valid",privGeoMarktCommitmentStorageHelper.isValid());
        Assert.assertTrue("privGeoMarktSearchableStorageHelper contracts are not valid",privGeoMarktSearchableStorageHelper.isValid());

        for (Contract contract : privGeoMarktHelper.getOwnersContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarkt);
        }

        for (Contract contract : privGeoMarktHelper.getBuyersContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarkt);
        }

        for (Contract contract : privGeoMarktHelper.getCuratorsContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarkt);
        }

        for (Contract contract : privGeoMarktCommitmentStorageHelper.getOwnersContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarktCommitmentStorage);
        }

        for (Contract contract : privGeoMarktCommitmentStorageHelper.getBuyersContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarktCommitmentStorage);
        }

        for (Contract contract : privGeoMarktCommitmentStorageHelper.getCuratorsContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarktCommitmentStorage);
        }

        for (Contract contract : privGeoMarktSearchableStorageHelper.getOwnersContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarktSearchableStorage);
        }

        for (Contract contract : privGeoMarktSearchableStorageHelper.getBuyersContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarktSearchableStorage);
        }

        for (Contract contract : privGeoMarktSearchableStorageHelper.getCuratorsContracts()) {
            Assert.assertTrue("Contract type mismatch", contract instanceof PrivGeoMarktSearchableStorage);
        }
    }

    @Test
    public void testPurchasePolicy() {
        try {
            int ownerIndex = 0;
            String ownerAddress = EthHelper.getOwnerAccounts().get(ownerIndex).getAddress();

            Contract ownerPrivGeoMarktContract = privGeoMarktHelper
                .getOwnersContracts()
                .get(ownerIndex);

            Assert.assertTrue("Contract type mismatch", ownerPrivGeoMarktContract instanceof PrivGeoMarkt);

            PrivGeoMarkt ownerPrivGeoMarkt = (PrivGeoMarkt) ownerPrivGeoMarktContract;

            Assert.assertTrue("Contract is not valid", ownerPrivGeoMarkt.isValid());

            double minPrice = OWNER_MIN_PRICE;
            ownerPrivGeoMarkt
                .createPurchasePolicy(Convert.toWei(BigDecimal.valueOf(minPrice), Convert.Unit.ETHER).toBigInteger())
                .send();
            BigInteger purchasePolicyInt = ownerPrivGeoMarkt.getPurchasePolicyOfOwner(ownerAddress).send();
            BigDecimal purchasePolicy = Convert.fromWei(BigDecimal.valueOf(purchasePolicyInt.longValue()), Convert.Unit.ETHER);

            Assert.assertEquals("Purchase policy does not match", minPrice, purchasePolicy.doubleValue(), 1e-12);

            ownerPrivGeoMarkt.deletePurchasePolicy().send();

            purchasePolicyInt = ownerPrivGeoMarkt.getPurchasePolicyOfOwner(ownerAddress).send();
            purchasePolicy = Convert.fromWei(BigDecimal.valueOf(purchasePolicyInt.longValue()), Convert.Unit.ETHER);

            Assert.assertEquals("Purchase policy is not deleted", 0, purchasePolicy.doubleValue(), 1e-12);

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }


    @Test
    public void testPurchasePolicyAsync() {
        List<CompletableFuture> completableFutures = new ArrayList<>();
        try {
            for (int ownerIndex = 0; ownerIndex < privGeoMarktHelper.getOwnersContracts().size(); ownerIndex++) {
                String ownerAddress = EthHelper.getOwnerAccounts().get(ownerIndex).getAddress();

                PrivGeoMarkt ownerPrivGeoMarkt = (PrivGeoMarkt) privGeoMarktHelper
                    .getOwnersContracts()
                    .get(ownerIndex);

                double minPrice = OWNER_MIN_PRICE;

                CompletableFuture<TransactionReceipt> receiptCompletableFuture = ownerPrivGeoMarkt
                    .createPurchasePolicy(Convert.toWei(BigDecimal.valueOf(minPrice), Convert.Unit.ETHER).toBigInteger())
                    .sendAsync();
                CompletableFuture<BigDecimal> purcharsePolicyFuture = receiptCompletableFuture.thenApply((TransactionReceipt receipt) -> {
                    try {
                        BigInteger purchasePolicyInt = ownerPrivGeoMarkt.getPurchasePolicyOfOwner(ownerAddress).send();
                        BigDecimal purchasePolicy = Convert.fromWei(BigDecimal.valueOf(purchasePolicyInt.longValue()), Convert.Unit.ETHER);
                        return purchasePolicy;
                    } catch (Exception e) {
                        return null;
                    }
                }).exceptionally(transactionReceipt -> null);

                purcharsePolicyFuture.thenAccept((BigDecimal purchasePolicy) -> {
                    Assert.assertEquals("Purchase policy does not match", minPrice, purchasePolicy.doubleValue(), 1e-12);
                });

                completableFutures.add(receiptCompletableFuture);
                completableFutures.add(purcharsePolicyFuture);
            }

            CompletableFuture<Void> allCompleted = CompletableFuture.allOf(completableFutures.toArray(new CompletableFuture[completableFutures.size()]));
            allCompleted.get();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

       
      /*@Test
  public void testCommitment() {
        try {
            int ownerIndex = 0;
            String ownerAddress = EthHelper.getOwnerAccounts().get(ownerIndex).getAddress();
            Contract ownerCommitmentStorageContract = privGeoMarktCommitmentStorageHelper
                .getOwnersContracts()
                .get(ownerIndex);

            Assert.assertTrue("Contract type mismatch", ownerCommitmentStorageContract instanceof PrivGeoMarktCommitmentStorage);

            PrivGeoMarktCommitmentStorage ownerCommimentStorage = (PrivGeoMarktCommitmentStorage) ownerCommitmentStorageContract;

            Assert.assertTrue("Contract is not valid", ownerCommimentStorage.isValid());

            //delete owner
            ownerCommimentStorage.deleteOwner().send();

            int prevOwnerCount = ownerCommimentStorage.getOwnerCount().send().intValue();

            int numCommitments = ownerCommimentStorage.getNumCommitments(ownerAddress).send().intValue();
            Assert.assertEquals("Number of commitments before submitting mismatch", 0, numCommitments);

            boolean didHaveCommitments = ownerCommimentStorage.didOwnerHaveCommitments(ownerAddress).send();
            Assert.assertFalse("didHaveCommitments failed", didHaveCommitments);


            //submit 1 commitment

            String dataAddress = DATA_ADDRESS;
            String commitment = COMMITMENT;

            ownerCommimentStorage.submitCommitment(dataAddress.getBytes(), commitment.getBytes()).send();

            numCommitments = ownerCommimentStorage.getNumCommitments(ownerAddress).send().intValue();
            Assert.assertEquals("Number of commitments after submitting mismatch", 1, numCommitments);

            Assert.assertEquals("Data address mismatch",
                dataAddress,
                new String(ownerCommimentStorage.commitmentsIndicesMapping(ownerAddress, BigInteger.valueOf(0)).send()));

            didHaveCommitments = ownerCommimentStorage.didOwnerHaveCommitments(ownerAddress).send();
            Assert.assertTrue("didHaveCommitments failed", didHaveCommitments);

            boolean didCommitmentHaveData = ownerCommimentStorage.didCommitmentHaveData(ownerAddress, dataAddress.getBytes()).send();
            Assert.assertTrue("didCommitmentHaveData failed", didCommitmentHaveData);

            Tuple2<byte[], BigInteger> commitmentTuple2 = ownerCommimentStorage.getCommitment(ownerAddress, dataAddress.getBytes()).send();
            Assert.assertEquals("Mismatch commitment", commitment, new String(commitmentTuple2.getValue1()));

            int currOwnerCount = ownerCommimentStorage.getOwnerCount().send().intValue();
            Assert.assertTrue("Owner coutn failed", currOwnerCount == prevOwnerCount + 1);


            //delete owner's only commitment
            ownerCommimentStorage.deleteCommitment(dataAddress.getBytes()).send();

            numCommitments = ownerCommimentStorage.getNumCommitments(ownerAddress).send().intValue();
            Assert.assertEquals("Number of commitments after deleting mismatch", 0, numCommitments);

            didHaveCommitments = ownerCommimentStorage.didOwnerHaveCommitments(ownerAddress).send();
            Assert.assertFalse("didHaveCommitments failed", didHaveCommitments);

            currOwnerCount = ownerCommimentStorage.getOwnerCount().send().intValue();
            Assert.assertTrue("Owner coutn failed", currOwnerCount == prevOwnerCount);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }*/


   /* @Test
    public void testSubmitSearchableIndex() {
        try {
            int curatorIndex = 0;
            String curatorAddress = EthHelper.getCuratorAccount().getAddress();
            Contract curatorSearchableStorageContract = privGeoMarktSearchableStorageHelper
                .getCuratorsContracts()
                .get(curatorIndex);

            Assert.assertTrue("Contract type mismatch", curatorSearchableStorageContract instanceof PrivGeoMarktSearchableStorage);

            PrivGeoMarktSearchableStorage curatorSearchableStorage = (PrivGeoMarktSearchableStorage) curatorSearchableStorageContract;


            Assert.assertTrue("Contract is not valid", curatorSearchableStorage.isValid());

            //delete curator
            curatorSearchableStorage.deleteCurator().send();

            int prevCount = curatorSearchableStorage.getCuratorCount().send().intValue();

            int numSearchableIndexInfos = curatorSearchableStorage.getNumSearchableIndexInfos(curatorAddress).send().intValue();
            Assert.assertEquals("numSearchableIndexInfos before submitting mismatch", 0, numSearchableIndexInfos);

            boolean didCuratorHaveSearchableIndexInfos = curatorSearchableStorage.didCuratorHaveSearchableIndexInfos(curatorAddress).send();
            Assert.assertFalse("didCuratorHaveSearchableIndexInfos failed", didCuratorHaveSearchableIndexInfos);


            //submit 1 searchable index

            String indexAddress = INDEX_ADDRESS;
            long startTime = START_TIME;
            long endTime = END_TIME;

            curatorSearchableStorage
                .submitSearchableIndex(
                    indexAddress.getBytes(),
                    BigInteger.valueOf(startTime),
                    BigInteger.valueOf(endTime))
                .send();

            numSearchableIndexInfos = curatorSearchableStorage.getNumSearchableIndexInfos(curatorAddress).send().intValue();
            Assert.assertEquals("numSearchableIndexInfos after submitting mismatch", 1, numSearchableIndexInfos);

            Assert.assertEquals("Index address mismatch",
                indexAddress,
                new String(curatorSearchableStorage.searchableIndexInfosIndexMapping(curatorAddress, BigInteger.valueOf(0)).send()));

            didCuratorHaveSearchableIndexInfos = curatorSearchableStorage.didCuratorHaveSearchableIndexInfos(curatorAddress).send();
            Assert.assertTrue("didCuratorHaveSearchableIndexInfos failed", didCuratorHaveSearchableIndexInfos);

            boolean didSearchableIndexInfoHaveData = curatorSearchableStorage.didSearchableIndexInfoHaveData(curatorAddress, indexAddress.getBytes()).send();
            Assert.assertTrue("didSearchableIndexInfoHaveData failed", didSearchableIndexInfoHaveData);

            Tuple3<BigInteger, BigInteger, BigInteger> searchableIndexInfoTimes = curatorSearchableStorage
                .getSearchableIndexInfo(curatorAddress, indexAddress.getBytes())
                .send();
            Assert.assertEquals("Start time mistmatched", startTime, searchableIndexInfoTimes.getValue1().longValue());
            Assert.assertEquals("End time mistmatched", endTime, searchableIndexInfoTimes.getValue2().longValue());

            int currCount = curatorSearchableStorage.getCuratorCount().send().intValue();
            Assert.assertTrue("Curator failed", currCount == prevCount + 1);


            //delete curator's only index
            curatorSearchableStorage.deleteSearchableIndex(indexAddress.getBytes()).send();

            numSearchableIndexInfos = curatorSearchableStorage.getNumSearchableIndexInfos(curatorAddress).send().intValue();
            Assert.assertEquals("numSearchableIndexInfos after deleting mismatch", 0, numSearchableIndexInfos);

            didCuratorHaveSearchableIndexInfos = curatorSearchableStorage.didCuratorHaveSearchableIndexInfos(curatorAddress).send();
            Assert.assertFalse("didCuratorHaveSearchableIndexInfos failed", didCuratorHaveSearchableIndexInfos);

            currCount = curatorSearchableStorage.getCuratorCount().send().intValue();
            Assert.assertTrue("Curator count failed", currCount == prevCount);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }

    }*/

    /**
     * Submit an offer
     * @param buyerIndex
     * @param ownerIndex
     * @param minPrice
     * @param lowerPrice
     * @param higherPrice
     * @param offerExpirationPeriod
     * @param refundExpirationPeriod
     * @param dataAddress
     * @return indexInOfferList
     */
    private BigInteger submitOffer(int buyerIndex, int ownerIndex,
                             double minPrice, double lowerPrice, double higherPrice,
                             long offerExpirationPeriod, long refundExpirationPeriod,
                             String dataAddress) {
        try {
			System.out.println("SubmitOffer");
            String buyerAddress = EthHelper.getBuyerAccounts().get(buyerIndex).getAddress();
            String ownerAddress = EthHelper.getOwnerAccounts().get(ownerIndex).getAddress();

            Contract ownerPrivGeoMarktContract = privGeoMarktHelper
                .getOwnersContracts()
                .get(ownerIndex);

            Assert.assertTrue("Contract type mismatch", ownerPrivGeoMarktContract instanceof PrivGeoMarkt);

            PrivGeoMarkt ownerPrivGeoMarkt = (PrivGeoMarkt) ownerPrivGeoMarktContract;

            Assert.assertTrue("Contract is not valid", ownerPrivGeoMarkt.isValid());

            Contract buyerPrivGeoMarktContract = privGeoMarktHelper
                .getBuyersContracts()
                .get(buyerIndex);

            Assert.assertTrue("Contract type mismatch", buyerPrivGeoMarktContract instanceof PrivGeoMarkt);

            PrivGeoMarkt buyerPrivGeoMarkt = (PrivGeoMarkt) buyerPrivGeoMarktContract;

            Assert.assertTrue("Contract is not valid", buyerPrivGeoMarkt.isValid());

            int prevNumOffersOfBuyer = buyerPrivGeoMarkt.getNumOffersOfBuyer(buyerAddress).send().intValue();
            int prevNumOffersOfOwners = buyerPrivGeoMarkt.getNumOffersOfOwners(ownerAddress).send().intValue();
            int prevNumOffers = buyerPrivGeoMarkt.getNumOffers().send().intValue();

	            //set min price
            ownerPrivGeoMarkt
                .createPurchasePolicy(Convert.toWei(BigDecimal.valueOf(minPrice), Convert.Unit.ETHER).toBigInteger())
                .send();
            BigInteger purchasePolicyInt = ownerPrivGeoMarkt.getPurchasePolicyOfOwner(ownerAddress).send();
            BigDecimal purchasePolicy = Convert.fromWei(BigDecimal.valueOf(purchasePolicyInt.longValue()), Convert.Unit.ETHER);

            Assert.assertEquals("Purchase policy does not match", minPrice, purchasePolicy.doubleValue(), 1e-12);

            long currentTime = Utils.currentTimeInSeconds(); //time in seconds
            long offerExpiration = currentTime + offerExpirationPeriod;
            long refundExpiration = currentTime + refundExpirationPeriod;

            //invalid price
            double price = lowerPrice; //ether
            BigInteger priceInWei = Convert.toWei(BigDecimal.valueOf(price), Convert.Unit.ETHER).toBigInteger();

            ArrayList<byte[]> dataAddressesToPurchase = new ArrayList<>();
            dataAddressesToPurchase.add(dataAddress.getBytes());

            EthGetBalance prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();
				 try {
					// invalid offer
					TransactionReceipt receipt = buyerPrivGeoMarkt
						.makeOffer(ownerAddress,
							dataAddressesToPurchase,
							BigInteger.valueOf(offerExpiration),
							BigInteger.valueOf(refundExpiration),
							priceInWei)
						.send();
					//Assert.Fail("No exception was thrown");
						System.out.println("No exception was thrown");
				} catch(RuntimeException e) {
					System.out.println(e);
				}
          
            boolean satisfied = buyerPrivGeoMarkt.isSatisfiable(ownerAddress, dataAddressesToPurchase, priceInWei).send();

            Assert.assertFalse("Invalid satisfied offer", satisfied);

            //check balance
            //EthGetBalance failTxBalance = web3j
              //  .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
               // .send();

            // remaining balance = previous balance - gas used
            //Assert.assertEquals(
              //  prevBalance.getBalance().subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_MAKEOFFER))),
               // failTxBalance.getBalance());

            //same number of offers
            Assert.assertTrue(prevNumOffersOfBuyer == buyerPrivGeoMarkt.getNumOffersOfBuyer(buyerAddress).send().intValue());
            Assert.assertTrue(prevNumOffersOfOwners == buyerPrivGeoMarkt.getNumOffersOfOwners(ownerAddress).send().intValue());
            Assert.assertTrue(prevNumOffers == buyerPrivGeoMarkt.getNumOffers().send().intValue());

            //valid price
            price = higherPrice;
            priceInWei = Convert.toWei(BigDecimal.valueOf(price), Convert.Unit.ETHER).toBigInteger();

            prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // valid offer
            TransactionReceipt receipt = buyerPrivGeoMarkt
                .makeOffer(ownerAddress,
                    dataAddressesToPurchase,
                    BigInteger.valueOf(offerExpiration),
                    BigInteger.valueOf(refundExpiration),
                    priceInWei)
                .send();

            satisfied = buyerPrivGeoMarkt.isSatisfiable(ownerAddress, dataAddressesToPurchase, priceInWei).send();

            Assert.assertTrue("Invalid satisfied offer", satisfied);

            //check balance
            EthGetBalance successTxBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used - price
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_MAKEOFFER)))
                    .subtract(priceInWei),
                successTxBalance.getBalance());

            //== number of offers + 1
            BigInteger numOfferOfBuyer = buyerPrivGeoMarkt.getNumOffersOfBuyer(buyerAddress).send();
            BigInteger numOfferOfOwner = ownerPrivGeoMarkt.getNumOffersOfOwners(ownerAddress).send();
            BigInteger numOffers = buyerPrivGeoMarkt.getNumOffers().send();
            Assert.assertTrue(prevNumOffersOfBuyer + 1 == numOfferOfBuyer.intValue());
            Assert.assertTrue(prevNumOffersOfOwners + 1 == numOfferOfOwner.intValue());
            Assert.assertTrue(prevNumOffers + 1 == numOffers.intValue());

            BigInteger indexInOfferList = buyerPrivGeoMarkt.offersOfBuyer(buyerAddress, numOfferOfBuyer.subtract(BigInteger.valueOf(1))).send();

            Assert.assertTrue(buyerPrivGeoMarkt.isValidOfferMapping(indexInOfferList).send());

            Assert.assertEquals("Indices mismatch",
                indexInOfferList,
                ownerPrivGeoMarkt.offersOfOwner(ownerAddress, numOfferOfOwner.subtract(BigInteger.valueOf(1))).send());

            //check content
            Tuple6<String, String, BigInteger, BigInteger, BigInteger, List<byte[]>> offerContributors = buyerPrivGeoMarkt.getOfferContributors(indexInOfferList).send();
            String offerBuyerAddress = offerContributors.getValue1();
            Assert.assertEquals(buyerAddress, offerBuyerAddress);

            String offerOwnerAddress = offerContributors.getValue2();
            Assert.assertEquals(ownerAddress, offerOwnerAddress);

            BigInteger offerValue = offerContributors.getValue3();
            Assert.assertEquals(priceInWei, offerValue);

            BigInteger inOwnerIndex = offerContributors.getValue4();
            Assert.assertTrue(numOfferOfOwner.intValue() - 1 == inOwnerIndex.intValue());

            BigInteger inBuyerIndex = offerContributors.getValue5();
            Assert.assertTrue(numOfferOfBuyer.intValue() - 1 == inBuyerIndex.intValue());

            List<byte[]> offerDataAddresses = offerContributors.getValue6();
            Assert.assertEquals(dataAddressesToPurchase.size(), offerDataAddresses.size());
            for (int i = 0; i < dataAddressesToPurchase.size(); i++) {
                Assert.assertTrue(Arrays.equals(dataAddressesToPurchase.get(i), offerDataAddresses.get(i)));
            }

            Tuple2<BigInteger, BigInteger> offerTimes = buyerPrivGeoMarkt.getOfferExpirationTimes(indexInOfferList).send();
            Assert.assertEquals(offerExpiration, offerTimes.getValue1().longValue());
            Assert.assertEquals(refundExpiration, offerTimes.getValue2().longValue());

            BigInteger offerStatus = buyerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.PENDING.getValue());
			System.out.println("Return index: " +indexInOfferList);
            return indexInOfferList;

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);

            return null;
        }
    }

    @Test
    public void testSubmitOffer() {
		System.out.println("Running testSubmitOffer");
        int buyerIndex = 0;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = OFFER_EXPIRATION;
        long refundExpirationPeriod = REFUND_EXPIRATION;
        String dataAddress = DATA_ADDRESS;
        submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);
    }

    @Test
    public void testCancelOfferBeforeKeysBeingSent() {
		System.out.println("Running testCancelOfferBeforeKeysBeingSent");
        int buyerIndex = 0;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = OFFER_EXPIRATION;
        long refundExpirationPeriod = REFUND_EXPIRATION;
        String dataAddress = DATA_ADDRESS;
        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        if (indexInOfferList == null) return;
        try {
            String buyerAddress = EthHelper.getBuyerAccounts().get(buyerIndex).getAddress();

            Contract buyerPrivGeoMarktContract = privGeoMarktHelper
                .getBuyersContracts()
                .get(buyerIndex);

            PrivGeoMarkt buyerPrivGeoMarkt = (PrivGeoMarkt) buyerPrivGeoMarktContract;

            EthGetBalance prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // cancel
            TransactionReceipt receipt = buyerPrivGeoMarkt
                .cancelOffer(indexInOfferList)
                .send();

            //check content
            Tuple6<String, String, BigInteger, BigInteger, BigInteger, List<byte[]>> offerContributors = buyerPrivGeoMarkt.getOfferContributors(indexInOfferList).send();
            BigInteger offerValue = offerContributors.getValue3();

            //check balance
            EthGetBalance successTxBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used + offer_value
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_CANCELOFFER)))
                    .add(offerValue),
                successTxBalance.getBalance());

            // status == CANCELED
            BigInteger offerStatus = buyerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.CANCELED.getValue());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

    private TransactionReceipt sendKeys(BigInteger indexInOfferList,
                                        byte[] encryptedKeys,
                                        BigInteger numKeys,
                                        int ownerIndex) {
        try {
            String ownerAddress = EthHelper.getOwnerAccounts().get(ownerIndex).getAddress();
            Contract ownerPrivGeoMarktContract = privGeoMarktHelper
                .getOwnersContracts()
                .get(ownerIndex);

            PrivGeoMarkt ownerPrivGeoMarkt = (PrivGeoMarkt) ownerPrivGeoMarktContract;

            EthGetBalance prevBalance = web3j
                .ethGetBalance(ownerAddress, DefaultBlockParameterName.LATEST)
                .send();

            TransactionReceipt receipt = ownerPrivGeoMarkt
                .sendKeys(indexInOfferList, encryptedKeys, numKeys)
                .send();

            //check content
            Tuple2<byte[], BigInteger> offerKeysTuple = ownerPrivGeoMarkt.getOfferKeys(indexInOfferList).send();
            Assert.assertTrue(Arrays.equals(encryptedKeys, offerKeysTuple.getValue1()));
            Assert.assertEquals(numKeys, offerKeysTuple.getValue2());

            //check balance
            EthGetBalance successTxBalance = web3j
                .ethGetBalance(ownerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_SENDKEYS))),
                successTxBalance.getBalance());

            // status == KEY_SUBMITTED
            BigInteger offerStatus = ownerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.KEYS_SUBMITTED.getValue());

            return receipt;
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
            return null;
        }
    }

    @Test
    public void testSendKeysBeforeCanceled() {
		System.out.println("Running testSendKeysBeforeCanceled");
        int buyerIndex = 0;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = OFFER_EXPIRATION;
        long refundExpirationPeriod = REFUND_EXPIRATION;
        String dataAddress = DATA_ADDRESS;
        byte[] encryptedKeys = ENCRYPTED_KEYS.getBytes();
        BigInteger numKeys = BigInteger.valueOf(NUM_ENCRYPTED_KEYS);

        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        if (indexInOfferList == null) return;
        try {
            // send keys
            sendKeys(indexInOfferList, encryptedKeys, numKeys, ownerIndex);
        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

    @Test
    public void testCancelOfferAfterKeysBeingSent() {
		System.out.println("Running testCancelOfferAfterKeysBeingSent");
        int buyerIndex = 0;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = OFFER_EXPIRATION;
        long refundExpirationPeriod = REFUND_EXPIRATION;
        String dataAddress = DATA_ADDRESS;
        byte[] encryptedKeys = ENCRYPTED_KEYS.getBytes();
        BigInteger numKeys = BigInteger.valueOf(NUM_ENCRYPTED_KEYS);

        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        if (indexInOfferList == null) return;
        try {

            //send keys
            sendKeys(indexInOfferList, encryptedKeys, numKeys, ownerIndex);

            //try cancel

            String buyerAddress = EthHelper.getBuyerAccounts().get(buyerIndex).getAddress();

            Contract buyerPrivGeoMarktContract = privGeoMarktHelper
                .getBuyersContracts()
                .get(buyerIndex);

            PrivGeoMarkt buyerPrivGeoMarkt = (PrivGeoMarkt) buyerPrivGeoMarktContract;

            EthGetBalance prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // failed cancel
            TransactionReceipt receipt = buyerPrivGeoMarkt
                .cancelOffer(indexInOfferList)
                .send();

            //check balance
            EthGetBalance failTxBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_CANCELOFFER))),
                failTxBalance.getBalance());

            // status == KEY_SUBMITTED
            BigInteger offerStatus = buyerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.KEYS_SUBMITTED.getValue());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

    @Test
    public void testWithdrawOfferBeforeKeysBeingSent() {
		System.out.println("Running testWithdrawOfferBeforeKeysBeingSent");
        int buyerIndex = 0;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = 60; //seconds, //should be enough time to send key
        long refundExpirationPeriod = 120; //minutes
        String dataAddress = DATA_ADDRESS;
        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        long submittedTime = Utils.currentTimeInSeconds();

        if (indexInOfferList == null) return;
        try {

            //NOT SEND KEY

            //try withdraw after refundExpirationPeriod
            while (Utils.currentTimeInSeconds() < submittedTime + refundExpirationPeriod) {
                Thread.sleep(5000);
            }

            String ownerAddress = EthHelper.getOwnerAccounts().get(ownerIndex).getAddress();
            Contract ownerPrivGeoMarktContract = privGeoMarktHelper
                .getOwnersContracts()
                .get(ownerIndex);

            PrivGeoMarkt ownerPrivGeoMarkt = (PrivGeoMarkt) ownerPrivGeoMarktContract;

            EthGetBalance prevBalance = web3j
                .ethGetBalance(ownerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // withdraw
            TransactionReceipt receipt = ownerPrivGeoMarkt
                .withdrawPayment(indexInOfferList)
                .send();

            //check balance
            EthGetBalance failTxBalance = web3j
                .ethGetBalance(ownerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_WITHDRAWPAYMENT))),
                failTxBalance.getBalance());


            // status == PENDING
            BigInteger offerStatus = ownerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.PENDING.getValue());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

    @Test
    public void testWithdrawOfferAfterKeysBeingSent() {
		System.out.println("Running testWithdrawOfferAfterKeysBeingSent");
        int buyerIndex = 3;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = 60; //should be enough time to send key
        long refundExpirationPeriod = 120; //2 minutes
        String dataAddress = DATA_ADDRESS;
        byte[] encryptedKeys = ENCRYPTED_KEYS.getBytes();
        BigInteger numKeys = BigInteger.valueOf(NUM_ENCRYPTED_KEYS);

        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        long submittedTime = Utils.currentTimeInSeconds();

        if (indexInOfferList == null) return;
        try {

            //send keys
            sendKeys(indexInOfferList, encryptedKeys, numKeys, ownerIndex);

            //try withdraw after refundExpirationPeriod
            while (Utils.currentTimeInSeconds() < submittedTime + refundExpirationPeriod) {
                Thread.sleep(5000);
            }

            String ownerAddress = EthHelper.getOwnerAccounts().get(ownerIndex).getAddress();
            Contract ownerPrivGeoMarktContract = privGeoMarktHelper
                .getOwnersContracts()
                .get(ownerIndex);

            PrivGeoMarkt ownerPrivGeoMarkt = (PrivGeoMarkt) ownerPrivGeoMarktContract;


            EthGetBalance prevBalance = web3j
                .ethGetBalance(ownerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // withdraw
            TransactionReceipt receipt = ownerPrivGeoMarkt
                .withdrawPayment(indexInOfferList)
                .send();

            //check balance
            EthGetBalance successTxBalance = web3j
                .ethGetBalance(ownerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used + value

            //get value
            Tuple6<String, String, BigInteger, BigInteger, BigInteger, List<byte[]>> offerContributors =
                ownerPrivGeoMarkt.getOfferContributors(indexInOfferList).send();
            BigInteger offerValue = offerContributors.getValue3();

            // remaining balance = previous balance - gas used + offer_value
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_WITHDRAWPAYMENT)))
                    .add(offerValue),
                successTxBalance.getBalance());


            // status == WITHDRAWN
            BigInteger offerStatus = ownerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.WITHDRAWN.getValue());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

    @Test
    public void testRefundOfferAfterRefundExpiration() {
		System.out.println("Running testRefundOfferAfterRefundExpiration");
        int buyerIndex = 0;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = 60; //should be enough time to send key
        long refundExpirationPeriod = 120;
        String dataAddress = DATA_ADDRESS;
        byte[] encryptedKeys = ENCRYPTED_KEYS.getBytes();
        BigInteger numKeys = BigInteger.valueOf(NUM_ENCRYPTED_KEYS);

        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        long submittedTime = Utils.currentTimeInSeconds();

        if (indexInOfferList == null) return;
        try {

            //send keys
            sendKeys(indexInOfferList, encryptedKeys, numKeys, ownerIndex);

            //try refund after refundExpirationPeriod
            while (Utils.currentTimeInSeconds() < submittedTime + refundExpirationPeriod) {
                Thread.sleep(5000);
            }

            String buyerAddress = EthHelper.getBuyerAccounts().get(buyerIndex).getAddress();

            Contract buyerPrivGeoMarktContract = privGeoMarktHelper
                .getBuyersContracts()
                .get(buyerIndex);

            PrivGeoMarkt buyerPrivGeoMarkt = (PrivGeoMarkt) buyerPrivGeoMarktContract;

            EthGetBalance prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // failed refund
            TransactionReceipt receipt = buyerPrivGeoMarkt
                .refundOffer(indexInOfferList)
                .send();

            //check balance
            EthGetBalance failTxBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_REFUNDOFFER))),
                failTxBalance.getBalance());

            // status == KEY_SUBMITTED
            BigInteger offerStatus = buyerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.KEYS_SUBMITTED.getValue());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

    @Test
    public void testRefundOfferShouldSuccess() {
		System.out.println("Running testRefundOfferShouldSuccess");
        int buyerIndex = 0;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = 60; //should be enough time to send key
        long refundExpirationPeriod = REFUND_EXPIRATION;
        String dataAddress = DATA_ADDRESS;
        byte[] encryptedKeys = ENCRYPTED_KEYS.getBytes();
        BigInteger numKeys = BigInteger.valueOf(NUM_ENCRYPTED_KEYS);

        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        long submittedTime = Utils.currentTimeInSeconds();

        if (indexInOfferList == null) return;
        try {

            //send keys
            sendKeys(indexInOfferList, encryptedKeys, numKeys, ownerIndex);

            //try refund after offerExpirationPeriod
            while (Utils.currentTimeInSeconds() < submittedTime + offerExpirationPeriod) {
                Thread.sleep(5000);
            }

            String buyerAddress = EthHelper.getBuyerAccounts().get(buyerIndex).getAddress();

            Contract buyerPrivGeoMarktContract = privGeoMarktHelper
                .getBuyersContracts()
                .get(buyerIndex);

            PrivGeoMarkt buyerPrivGeoMarkt = (PrivGeoMarkt) buyerPrivGeoMarktContract;

            EthGetBalance prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // success refund
            TransactionReceipt receipt = buyerPrivGeoMarkt
                .refundOffer(indexInOfferList)
                .send();


            //check balance
            EthGetBalance successTxBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used + value
            //get value
            Tuple6<String, String, BigInteger, BigInteger, BigInteger, List<byte[]>> offerContributors =
                buyerPrivGeoMarkt.getOfferContributors(indexInOfferList).send();
            BigInteger offerValue = offerContributors.getValue3();

            // remaining balance = previous balance - gas used + offer_value
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_REFUNDOFFER)))
                    .add(offerValue),
                successTxBalance.getBalance());

            // status == REFUNDED
            BigInteger offerStatus = buyerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.REFUNDED.getValue());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }

    @Test
    public void testRefundOfferTwice() {
		System.out.println("Running testRefundOfferTwice");
        int buyerIndex = 2;
        int ownerIndex = 0;
        double minPrice = OWNER_MIN_PRICE;
        double lowerPrice = OWNER_MIN_PRICE - 0.1;
        double higherPrice = OWNER_MIN_PRICE + 0.1;
        long offerExpirationPeriod = 120; //should be enough time to send key
        long refundExpirationPeriod = REFUND_EXPIRATION;
        String dataAddress = DATA_ADDRESS;
        byte[] encryptedKeys = ENCRYPTED_KEYS.getBytes();
        BigInteger numKeys = BigInteger.valueOf(NUM_ENCRYPTED_KEYS);
        BigInteger indexInOfferList = submitOffer(buyerIndex, ownerIndex, minPrice, lowerPrice, higherPrice, offerExpirationPeriod, refundExpirationPeriod, dataAddress);

        long submittedTime = Utils.currentTimeInSeconds();

        if (indexInOfferList == null) return;
        try {

            //send keys
            sendKeys(indexInOfferList, encryptedKeys, numKeys, ownerIndex);

            //try refund after offerExpirationPeriod
            while (Utils.currentTimeInSeconds() < submittedTime + offerExpirationPeriod) {
                Thread.sleep(5000);
            }

            String buyerAddress = EthHelper.getBuyerAccounts().get(buyerIndex).getAddress();

            Contract buyerPrivGeoMarktContract = privGeoMarktHelper
                .getBuyersContracts()
                .get(buyerIndex);

            PrivGeoMarkt buyerPrivGeoMarkt = (PrivGeoMarkt) buyerPrivGeoMarktContract;

            EthGetBalance prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // success refund
            TransactionReceipt receipt = buyerPrivGeoMarkt
                .refundOffer(indexInOfferList)
                .send();

            //check balance
            EthGetBalance successTxBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used + value
            //get value
            Tuple6<String, String, BigInteger, BigInteger, BigInteger, List<byte[]>> offerContributors =
                buyerPrivGeoMarkt.getOfferContributors(indexInOfferList).send();
            BigInteger offerValue = offerContributors.getValue3();

            // remaining balance = previous balance - gas used + offer_value
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_REFUNDOFFER)))
                    .add(offerValue),
                successTxBalance.getBalance());

            // status == REFUNDED
            BigInteger offerStatus = buyerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.REFUNDED.getValue());

            //REFUND ONE MORE TIME
            prevBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // success refund
            receipt = buyerPrivGeoMarkt
                .refundOffer(indexInOfferList)
                .send();

            //check balance
            EthGetBalance failTxBalance = web3j
                .ethGetBalance(buyerAddress, DefaultBlockParameterName.LATEST)
                .send();

            // remaining balance = previous balance - gas used

            // remaining balance = previous balance - gas used
            Assert.assertEquals(
                prevBalance.getBalance()
                    .subtract(receipt.getGasUsed().multiply(contractGasProvider.getGasPrice(PrivGeoMarkt.FUNC_REFUNDOFFER))),
                failTxBalance.getBalance());

            // status == REFUNDED
            offerStatus = buyerPrivGeoMarkt.getOfferStatus(indexInOfferList).send();
            Assert.assertTrue(offerStatus.intValue() == OfferStatus.REFUNDED.getValue());

        } catch (Exception e) {
            e.printStackTrace();
            Assert.assertTrue("Failed", false);
        }
    }
}
