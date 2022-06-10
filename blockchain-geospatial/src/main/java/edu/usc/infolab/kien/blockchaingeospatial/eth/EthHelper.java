package edu.usc.infolab.kien.blockchaingeospatial.eth;

import edu.usc.infolab.kien.blockchaingeospatial.config.Config;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.apache.logging.log4j.core.util.SystemClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Helper class for Ethereum network connections
 */
public class EthHelper {
    private static final Logger logger = LoggerFactory.getLogger(EthHelper.class);

    private static final String FUNDING_ACCOUNT_ADDRESS = "0xd03ea8624C8C5987235048901fB614fDcA89b117";
    private static final String CURATOR_ACCOUNT_ADDERSS = "0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0";
    private static final String BUYER_ACCOUNT_ADDRESS = "0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b";
    private static final String BUYER2_ACCOUNT_ADDRESS = "0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d";
    private static final String OWNER_ACCOUNT_ADDRESS = "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1";

    private static ArrayList<Credentials> allCredentials = new ArrayList<>();
    private static ArrayList<Credentials> ownerAccounts = new ArrayList<>();
    private static ArrayList<Credentials> buyerAccounts = new ArrayList<>();
    private static Credentials curatorAccount = null;
    private static Credentials fundingAccount = null;

    private static boolean credentialsLoaded = false;


    /**
     * Get Web3j connection to Ethereum network.
     *
     * Configuration should be loaded before calling this method.
     *
     * @return Web3j connection to Ethereum network
     * @throws IOException
     */
    public static Web3j getWeb3jConnection() throws IOException {
        Web3j web3j = Web3j.build(new HttpService(Config.getNetworkGeth()));
        logger.info("Connected to Ethereum client version: " + web3j.web3ClientVersion().send().getWeb3ClientVersion());

        return web3j;
    }

    /**
     * Get the first credentials to connect to Ethereum network.
     *
     * @return credentials to connect to Ethereum network.
     * @throws IOException
     * @throws CipherException
     */
    public static Credentials getCredentials() throws IOException, CipherException {
        return getCredentials(0);
    }

    /**
     * Get credentials to connect to Ethereum network.
     *
     * Configuration should be loaded before calling this method
     *
     * @return credentials to connect to Ethereum network or {@code null} if error occurred
     * @throws IOException
     * @throws CipherException
     */
    public static Credentials getCredentials(int index) throws IndexOutOfBoundsException {
        if (!credentialsLoaded)
            prepareCredentials();

        return allCredentials.get(index);
    }


    public static void prepareCredentials() {
        if (credentialsLoaded) {
            return;
        }

        try {
            allCredentials = new ArrayList<>();
            Credentials credentialsFunding = Credentials.create("0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");
            Credentials credentialsCurator = Credentials.create("0x6cbed15c793ce57650b9877cf6fa156fbef513c4e6134f022a85b1ffdd59b2a1");
            Credentials credentialsBuyer = Credentials.create("0x6370fd033278c143179d81c5526140625662b8daa446c22ee2d73db3707e620c");
            Credentials credentialsBuyer2 = Credentials.create("0x646f1ce2fdad0e6deeeb5c7e8e5543bdde65e86029e2fd9fc169899c440a7913");
            Credentials credentialsOwner = Credentials.create("0xadd53f9a7e588d003326d1cbf9e4a43c061aadd9bc938c843a79e7b4fd2ad743");

            //Load funding credentials
            fundingAccount = credentialsFunding;
            allCredentials.add(fundingAccount);

            //Load curator credentials
            curatorAccount = credentialsCurator;
            allCredentials.add(curatorAccount);

            if (fundingAccount == null) {
                logger.error("Unable to find funding account");
            } else {
                logger.info("Funding account address: " + fundingAccount.getAddress());
            }

            if (curatorAccount == null) {
                logger.error("Unable to find curator account");
            } else {
                logger.info("Curator account address: " + curatorAccount.getAddress());
            }

            //Load owners and buyers
            ownerAccounts.add(credentialsOwner);
            buyerAccounts.add(credentialsBuyer);
            buyerAccounts.add(credentialsBuyer2);
            allCredentials.add(credentialsOwner);
            allCredentials.add(credentialsBuyer);
            allCredentials.add(credentialsBuyer2);


            logger.info("There are " + ownerAccounts.size() + " owner accounts");
            logger.info("There are " + buyerAccounts.size() + " buyer accounts");


            credentialsLoaded = true;

            logger.info("Loaded " + allCredentials.size() + " credentials");
        } catch (Exception e) {
            logger.error("Error preparing credential", e);
        }
    }

    public static Credentials getFundingAccount() {
        if (!credentialsLoaded) {
            prepareCredentials();
        }

        return fundingAccount;
    }

    public static Credentials getCuratorAccount() {
        if (!credentialsLoaded) {
            prepareCredentials();
        }

        return curatorAccount;
    }

    public static ArrayList<Credentials> getOwnerAccounts() {
        if (!credentialsLoaded) {
            prepareCredentials();
        }

        return ownerAccounts;
    }

    public static ArrayList<Credentials> getBuyerAccounts() {
        if (!credentialsLoaded) {
            prepareCredentials();
        }

        return buyerAccounts;
    }

    public static BigDecimal getBalance(Web3j web3j, String address) throws IOException {
        if (web3j == null || address == null) {
            return null;
        }
        BigInteger balance = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send().getBalance();
        return Convert.fromWei(String.valueOf(balance), Convert.Unit.ETHER);
    }

    /**
     * Conver String to Eth Byte32
     * @param string
     * @return
     */
    public static Bytes32 converStringToBytes32(String string) {
        byte[] byteValue = string.getBytes();
        byte[] byteValueLen32 = new byte[32];
        System.arraycopy(byteValue, 0, byteValueLen32, 0, byteValue.length);
        return new Bytes32(byteValueLen32);
    }

    /**
     * Convert Eth Byte32 to String
     * @param value
     * @return
     */
    public static String convertByte32ToString(Bytes32 value) {
        return StringUtils.newStringUsAscii(value.getValue());
    }
}
