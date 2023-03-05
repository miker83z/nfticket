const NFTicket = artifacts.require('./NFTicket.sol');
const Verify = artifacts.require('Verify');
const ClaimsVerifier = artifacts.require('ClaimsVerifier');

module.exports = async (deployer, network, addresses) => {
  let proxyRegistryAddress = '0xa5409ec958c83c3f309868babaca7c86dcb077c1';
  const baseUri = 'ipfs://QmUemLVwFbD6$1Pj2rnHvtub516fSB7Ten4YmrLs7QyqDU/';
  const vp = await Verify.deployed();
  const verifier = await ClaimsVerifier.deployed();

  await deployer.deploy(
    NFTicket,
    baseUri,
    proxyRegistryAddress,
    vp.address,
    verifier.address
  );
};
