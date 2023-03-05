const CredentialRegistry = artifacts.require('CredentialRegistry');
const ClaimsVerifier = artifacts.require('ClaimsVerifier');

module.exports = async (deployer, network, addresses) => {
  await deployer.deploy(CredentialRegistry);
  const registry = await CredentialRegistry.deployed();
  await deployer.deploy(ClaimsVerifier, registry.address);
  const verifier = await ClaimsVerifier.deployed();
  await registry.grantRole(await registry.ISSUER_ROLE(), verifier.address);
};
