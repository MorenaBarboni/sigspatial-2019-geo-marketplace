/*
 * NB: since truffle-hdwallet-provider 0.0.5 you must wrap HDWallet providers in a 
 * function when declaring them. Failure to do so will cause commands to hang. ex:
 * ```
 * mainnet: {
 *     provider: function() { 
 *       return new HDWalletProvider(mnemonic, 'https://mainnet.infura.io/<infura-key>') 
 *     },
 *     network_id: '1',
 *     gas: 4500000,
 *     gasPrice: 10000000000,
 *   },
 */

require('babel-register')
module.exports = {
	 compilers: {
		solc: {
			version: "0.4.24"
		},
	},
  networks: {
    development: {
      host: 'localhost',
      port: 8545,
      network_id: '*'
	  }
  }
}
