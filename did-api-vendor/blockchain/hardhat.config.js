require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

module.exports = {
  solidity: "0.8.24",
  networks: {
    arbitrumSepolia: {
      url: process.env.ARB_SEPOLIA_RPC,
      accounts: [process.env.PRIVATE_KEY]
    }
  }
};
