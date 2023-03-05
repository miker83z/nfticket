const fs = require('fs');
const Web3 = require('web3');
const BN = Web3.utils.BN;

const crypto = require('crypto');
const moment = require('moment');
const web3Abi = require('web3-eth-abi');
const web3Utils = require('web3-utils');
const ethUtil = require('ethereumjs-util');

const NFTicket = artifacts.require('NFTicket');
const CredentialRegistry = artifacts.require('CredentialRegistry');
const ClaimsVerifier = artifacts.require('ClaimsVerifier');

const VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3(
  'VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)'
);
const EIP712DOMAIN_TYPEHASH = web3Utils.soliditySha3(
  'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
);

const sleep = (seconds) =>
  new Promise((resolve) => setTimeout(resolve, seconds * 1e3));

function sha256(data) {
  const hashFn = crypto.createHash('sha256');
  hashFn.update(data);
  return hashFn.digest('hex');
}

function getCredentialHash(vc, issuer, claimsVerifierContractAddress) {
  const hashDiplomaHex = `0x${sha256(JSON.stringify(vc.credentialSubject))}`;

  const encodeEIP712Domain = web3Abi.encodeParameters(
    ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
    [
      EIP712DOMAIN_TYPEHASH,
      web3Utils.sha3('EIP712Domain'),
      web3Utils.sha3('1'),
      648529,
      claimsVerifierContractAddress,
    ]
  );
  const hashEIP712Domain = web3Utils.soliditySha3(encodeEIP712Domain);

  const validFrom = new Date(vc.issuanceDate).getTime();
  const validTo = new Date(vc.expirationDate).getTime();
  const subjectAddress = vc.credentialSubject.id.split(':').slice(-1)[0];
  const encodeHashCredential = web3Abi.encodeParameters(
    ['bytes32', 'address', 'address', 'bytes32', 'uint256', 'uint256'],
    [
      VERIFIABLE_CREDENTIAL_TYPEHASH,
      issuer.address,
      subjectAddress,
      hashDiplomaHex,
      Math.round(validFrom / 1000),
      Math.round(validTo / 1000),
    ]
  );
  const hashCredential = web3Utils.soliditySha3(encodeHashCredential);

  const encodedCredentialHash = web3Abi.encodeParameters(
    ['bytes32', 'bytes32'],
    [hashEIP712Domain, hashCredential.toString(16)]
  );
  return web3Utils.soliditySha3(
    '0x1901'.toString(16) + encodedCredentialHash.substring(2, 131)
  );
}

function signCredential(credentialHash, issuer) {
  const rsv = ethUtil.ecsign(
    Buffer.from(credentialHash.substring(2, 67), 'hex'),
    Buffer.from(issuer.privateKey, 'hex')
  );
  return ethUtil.toRpcSig(rsv.v, rsv.r, rsv.s);
}

function load_test_file(name) {
  const fileJson = fs.readFileSync('./test/' + name + '.json', 'utf8');
  const obj = JSON.parse(fileJson);
  return obj;
}

function bnToBnHex(bn) {
  const bnStr = bn.toString(16);

  let enc_zeros = '';
  while ((enc_zeros + bnStr).length % 64 != 0) enc_zeros += '0';

  const concat = '0x' + enc_zeros + bnStr;

  return concat;
}

function decStrToBnHex(str) {
  const bn = new BN(str, 10);
  return bnToBnHex(bn);
}

contract('NFTicket', (accounts) => {
  const subject = accounts[1];
  const issuer = {
    address: accounts[0], //'0x70c0D1904aa32a40d146c9C45a7CB883ea7fE84C'
    privateKey:
      '8115bf21f49fd36bd384827a830e843c9b4951dd663d9f60196a3bbea2237619',
  };
  const signers = [
    {
      address: accounts[2], //'0x51Ad92b60dF169B631b77BBe509938adFF7acec9'
      privateKey:
        'fd8bcc98a94bc4d592c5178ea77cc5f6ca5d4d662f913f13dbc37526caced2ca',
    },
    {
      address: accounts[3], //'0xB99Ca2eBa205C5c7A7969db2dba4914793C1cA3a'
      privateKey:
        '0aae4bc1948e3cde1dcc8a9b52ce5e5a38b0564f8f00302a9d082d0f53f50807',
    },
  ];

  const full_proof = load_test_file('proof_predicates_without_revocation');
  const proof = full_proof.proof;

  const vc = {
    '@context': 'https://www.w3.org/2018/credentials/v1',
    id: '73bde252-cb3e-44ab-94f9-eba6a8a2f28d',
    type: 'VerifiableCredential',
    issuer: `did:lac:main:${issuer.address}`,
    issuanceDate: moment().toISOString(),
    expirationDate: moment().add(1, 'years').toISOString(),
    credentialSubject: {
      id: `did:lac:main:${subject}`,
      data: proof,
    },
    proof: [],
  };

  before(async () => {
    const instance = await ClaimsVerifier.deployed();
    await instance.grantRole(await instance.ISSUER_ROLE(), issuer.address);
    await instance.grantRole(await instance.SIGNER_ROLE(), signers[0].address);
    await instance.grantRole(await instance.SIGNER_ROLE(), signers[1].address);
  });

  /*
  it('should register a VC', async () => {
    const instance = await ClaimsVerifier.deployed();

    const credentialHash = getCredentialHash(vc, issuer, instance.address);
    const signature = await signCredential(credentialHash, issuer);

    const tx = await instance.registerCredential(
      subject,
      credentialHash,
      Math.round(moment(vc.issuanceDate).valueOf() / 1000),
      Math.round(moment(vc.expirationDate).valueOf() / 1000),
      signature,
      { from: issuer.address }
    );

    vc.proof.push({
      id: vc.issuer,
      type: 'EcdsaSecp256k1Signature2019',
      proofPurpose: 'assertionMethod',
      verificationMethod: `${vc.issuer}#vm-0`,
      domain: instance.address,
      proofValue: signature,
    });

    await sleep(1);

    return assert.equal(tx.receipt.status, true);
  });

  it('should fail verify additional signers', async () => {
    const instance = await ClaimsVerifier.deployed();

    const data = `0x${sha256(JSON.stringify(vc.credentialSubject))}`;
    const rsv = ethUtil.fromRpcSig(vc.proof[0].proofValue);
    const result = await instance.verifyCredential(
      [
        vc.issuer.replace('did:lac:main:', ''),
        vc.credentialSubject.id.replace('did:lac:main:', ''),
        data,
        Math.round(moment(vc.issuanceDate).valueOf() / 1000),
        Math.round(moment(vc.expirationDate).valueOf() / 1000),
      ],
      rsv.v,
      rsv.r,
      rsv.s
    );

    const additionalSigners = result[3];

    assert.equal(additionalSigners, false);
  });

  it('should register additional signatures to the VC', async () => {
    const instance = await ClaimsVerifier.deployed();

    const credentialHash = getCredentialHash(vc, issuer, instance.address);
    const signature1 = await signCredential(credentialHash, signers[0]);

    const tx1 = await instance.registerSignature(
      credentialHash,
      issuer.address,
      signature1,
      { from: signers[0].address }
    );

    vc.proof.push({
      id: `did:lac:main:${signers[0]}`,
      type: 'EcdsaSecp256k1Signature2019',
      proofPurpose: 'assertionMethod',
      verificationMethod: `did:lac:main:${signers[0]}#vm-0`,
      domain: instance.address,
      proofValue: signature1,
    });

    assert.equal(tx1.receipt.status, true);

    const signature2 = await signCredential(credentialHash, signers[1]);
    const tx2 = await instance.registerSignature(
      credentialHash,
      issuer.address,
      signature2,
      { from: signers[1].address }
    );

    vc.proof.push({
      id: `did:lac:main:${signers[1]}`,
      type: 'EcdsaSecp256k1Signature2019',
      proofPurpose: 'assertionMethod',
      verificationMethod: `did:lac:main:${signers[1]}#vm-0`,
      domain: instance.address,
      proofValue: signature2,
    });

    await sleep(1);

    return assert.equal(tx2.receipt.status, true);
  });

  it('should verify a VC', async () => {
    const instance = await ClaimsVerifier.deployed();
    // console.log( vc );

    const data = `0x${sha256(JSON.stringify(vc.credentialSubject))}`;
    const rsv = ethUtil.fromRpcSig(vc.proof[0].proofValue);
    const result = await instance.verifyCredential(
      [
        vc.issuer.replace('did:lac:main:', ''),
        vc.credentialSubject.id.replace('did:lac:main:', ''),
        data,
        Math.round(moment(vc.issuanceDate).valueOf() / 1000),
        Math.round(moment(vc.expirationDate).valueOf() / 1000),
      ],
      rsv.v,
      rsv.r,
      rsv.s
    );

    const credentialExists = result[0];
    const isNotRevoked = result[1];
    const issuerSignatureValid = result[2];
    const additionalSigners = result[3];
    const isNotExpired = result[4];

    assert.equal(credentialExists, true);
    assert.equal(isNotRevoked, true);
    assert.equal(issuerSignatureValid, true);
    assert.equal(additionalSigners, true);
    assert.equal(isNotExpired, true);
  });

  it('should verify additional signatures', async () => {
    const instance = await ClaimsVerifier.deployed();

    const data = `0x${sha256(JSON.stringify(vc.credentialSubject))}`;

    const sign1 = await instance.verifySigner(
      [
        vc.issuer.replace('did:lac:main:', ''),
        vc.credentialSubject.id.replace('did:lac:main:', ''),
        data,
        Math.round(moment(vc.issuanceDate).valueOf() / 1000),
        Math.round(moment(vc.expirationDate).valueOf() / 1000),
      ],
      vc.proof[1].proofValue
    );

    assert.equal(sign1, true);

    const sign2 = await instance.verifySigner(
      [
        vc.issuer.replace('did:lac:main:', ''),
        vc.credentialSubject.id.replace('did:lac:main:', ''),
        data,
        Math.round(moment(vc.issuanceDate).valueOf() / 1000),
        Math.round(moment(vc.expirationDate).valueOf() / 1000),
      ],
      vc.proof[2].proofValue
    );

    assert.equal(sign2, true);
  });

  it('should revoke the credential', async () => {
    const instance = await ClaimsVerifier.deployed();
    const registry = await CredentialRegistry.deployed();

    const credentialHash = getCredentialHash(vc, issuer, instance.address);

    const tx = await registry.revokeCredential(credentialHash);

    assert.equal(tx.receipt.status, true);
  });

  it('should fail the verification process due credential status', async () => {
    const instance = await ClaimsVerifier.deployed();

    const data = `0x${sha256(JSON.stringify(vc.credentialSubject))}`;
    const rsv = ethUtil.fromRpcSig(vc.proof[0].proofValue);
    const result = await instance.verifyCredential(
      [
        vc.issuer.replace('did:lac:main:', ''),
        vc.credentialSubject.id.replace('did:lac:main:', ''),
        data,
        Math.round(moment(vc.issuanceDate).valueOf() / 1000),
        Math.round(moment(vc.expirationDate).valueOf() / 1000),
      ],
      rsv.v,
      rsv.r,
      rsv.s
    );

    const isNotRevoked = result[1];

    assert.equal(isNotRevoked, false);
  });

  it('should verify credential status using the CredentialRegistry', async () => {
    const instance = await ClaimsVerifier.deployed();
    const registry = await CredentialRegistry.deployed();

    const credentialHash = getCredentialHash(vc, issuer, instance.address);

    const result = await registry.status(issuer.address, credentialHash);

    assert.equal(result, false);
  });
  */

  it('test_verify_predicate_proof_NFT_mint', async () => {
    const instance = await ClaimsVerifier.deployed();

    const credentialHash = getCredentialHash(vc, issuer, instance.address);
    const signature = await signCredential(credentialHash, issuer);

    const tx = await instance.registerCredential(
      subject,
      credentialHash,
      Math.round(moment(vc.issuanceDate).valueOf() / 1000),
      Math.round(moment(vc.expirationDate).valueOf() / 1000),
      signature,
      { from: issuer.address }
    );

    vc.proof.push({
      id: vc.issuer,
      type: 'EcdsaSecp256k1Signature2019',
      proofPurpose: 'assertionMethod',
      verificationMethod: `${vc.issuer}#vm-0`,
      domain: instance.address,
      proofValue: signature,
    });

    await sleep(1);

    const full_proof = load_test_file('proof_predicates_without_revocation');
    const proof = full_proof.proof;
    const requested_proof = full_proof.requested_proof; // sub_proof_request
    const pk = load_test_file('credential_primary_public_key');
    const credential_schema = load_test_file('credential_schema');
    const non_credential_schema = load_test_file('non_credential_schema');

    const two_596 = decStrToBnHex(
      '259344723055062059907025491480697571938277889515152306249728583105665800713306759149981690559193987143012367913206299323899696942213235956742929677132122730441323862712594345230336'
    );

    const z = decStrToBnHex(pk['z']);
    const z_inverted = bnToBnHex(new BN(pk['z'], 10).invm(new BN(pk['n'], 10)));

    const all_attrs = [
      ...credential_schema.attrs,
      ...non_credential_schema.attrs,
    ];
    const revealed_attrs = Object.keys(requested_proof.revealed_attrs);
    const revealed_attrs_values = revealed_attrs.map((e) =>
      decStrToBnHex(requested_proof['revealed_attrs'][e].encoded)
    );
    const unrevealed_attrs = all_attrs.filter(
      (e) => revealed_attrs.indexOf(e) === -1
    );

    const r_keys = Object.keys(pk.r);
    const r_values = r_keys.map((e) => decStrToBnHex(pk.r[e]));

    const verfiy_params = {
      nonce: [0xe0, 0xcc, 0xa9, 0x08, 0x49, 0xa2, 0xcf, 0xc3, 0x46, 0xc2],
      aggregated_proof_c_hash: decStrToBnHex(proof.aggregated_proof.c_hash),

      aggregated_proof_c_list: proof.aggregated_proof.c_list,
      primary_proofs: proof.proofs.map((p) => {
        const m_keys = Object.keys(p.primary_proof.eq_proof.m);
        const m_values = m_keys.map((e) =>
          decStrToBnHex(p.primary_proof.eq_proof.m[e])
        );

        const a_prime = decStrToBnHex(p.primary_proof.eq_proof.a_prime);
        const e = decStrToBnHex(p.primary_proof.eq_proof.e);
        const v = decStrToBnHex(p.primary_proof.eq_proof.v);
        const m2tilde = decStrToBnHex(p.primary_proof.eq_proof.m2);

        return {
          eq_proof: {
            // Calc_teq_param
            p_pub_key_n: decStrToBnHex(pk.n),
            p_pub_key_s: decStrToBnHex(pk.s),
            p_pub_key_rctxt: decStrToBnHex(pk.rctxt),
            unrevealed_attrs: unrevealed_attrs.map((e) => e.toLowerCase()),
            p_pub_key_r_keys: r_keys,
            p_pub_key_r_values: r_values,
            m_tilde_keys: m_keys,
            m_tilde_values: m_values,
            a_prime,
            e,
            v,
            m2tilde,
          },
          p_pub_key_z: z,
          p_pub_key_z_inverse: z_inverted,
          two_596: two_596,
          revealed_attrs: revealed_attrs.map((e) => e.toLowerCase()),
          revealed_attrs_values: revealed_attrs_values.map((e) =>
            e.toLowerCase()
          ),
          tne_params: p.primary_proof.ge_proofs.map((ge) => {
            const u_keys = Object.keys(ge.u);
            const u_values = u_keys.map((e) => decStrToBnHex(ge.u[e]));

            const r_keys = Object.keys(ge.r);
            const r_values = r_keys.map((e) => decStrToBnHex(ge.r[e]));

            const t_keys = Object.keys(ge.t);
            const t_values = t_keys.map((e) => decStrToBnHex(ge.t[e]));

            const is_less =
              ge['predicate']['p_type'].toUpperCase() === 'LE' ||
              ge['predicate']['p_type'].toUpperCase() === 'LT';

            var p_pub_key_s_invm = bnToBnHex(new BN(0));
            if (is_less) {
              const red = BN.red(new BN(pk.n, 10));
              const p_pub_key_s = new BN(pk.s, 10)
                .invm(new BN(pk.n, 10))
                .toRed(red);

              p_pub_key_s_invm = bnToBnHex(p_pub_key_s.fromRed());
            }

            return {
              p_pub_key_n: decStrToBnHex(pk.n),
              p_pub_key_z: decStrToBnHex(pk.z),
              p_pub_key_s: decStrToBnHex(pk.s),
              u_keys,
              u_values,
              r_keys,
              r_values,
              t_keys,
              t_values,
              is_less,
              mj: decStrToBnHex(ge.mj),
              alpha: decStrToBnHex(ge.alpha),
              p_pub_key_s_invm,
            };
          }),

          verify_ne_predicate_params: p.primary_proof.ge_proofs.map((ge) => {
            const is_less =
              ge['predicate']['p_type'].toUpperCase() === 'LE' ||
              ge['predicate']['p_type'].toUpperCase() === 'LT';

            const cur_t_inverse_keys = Object.keys(ge.t);
            const cur_t_inverse_values = cur_t_inverse_keys
              .map((t) => ge.t[t])
              .map((val) => new BN(val, 10))
              .map((bn) => bn.invm(new BN(pk.n, 10)))
              .map((bn) => bnToBnHex(bn));

            const proof_t_delta_inverse = new BN(ge['t']['DELTA'], 10).invm(
              new BN(pk['n'], 10)
            );

            const predicate_get_delta_prime = () => {
              if (ge['predicate']['p_type'] == 'GT') {
                return new BN(ge['predicate']['value'], 10).add(1);
              } else if (ge['predicate']['p_type'] == 'LT') {
                return new BN(ge['predicate']['value'], 10).sub(1);
              } else {
                return new BN(ge['predicate']['value'], 10);
              }
            };

            const tau_delta_intermediate_inverse = () => {
              const delta = new BN(ge['t']['DELTA'], 10);
              const delta_prime = is_less ? proof_t_delta_inverse : delta;

              const p_pub_key_n = new BN(pk['n'], 10);

              const red = BN.red(p_pub_key_n);

              let tau_delta_intermediate = new BN(pk['z'], 10).toRed(red);

              tau_delta_intermediate = tau_delta_intermediate.redPow(
                predicate_get_delta_prime()
              );
              tau_delta_intermediate = tau_delta_intermediate.redMul(
                delta_prime.toRed(red)
              );
              tau_delta_intermediate = tau_delta_intermediate.redPow(
                new BN(proof.aggregated_proof.c_hash, 10)
              );
              return tau_delta_intermediate.fromRed().invm(p_pub_key_n);
            };

            const tau_5_intermediate_inverse = () => {
              const delta = new BN(ge['t']['DELTA'], 10);
              const p_pub_key_n = new BN(pk['n'], 10);
              const red = BN.red(p_pub_key_n);

              let tau_5_intermediate_inverse = delta.toRed(red);
              tau_5_intermediate_inverse = tau_5_intermediate_inverse.redPow(
                new BN(proof.aggregated_proof.c_hash, 10)
              );
              return tau_5_intermediate_inverse.fromRed().invm(p_pub_key_n);
            };

            return {
              c_hash: decStrToBnHex(proof.aggregated_proof.c_hash),
              cur_t_inverse_keys,
              cur_t_inverse_values,
              proof_t_delta_inverse: bnToBnHex(proof_t_delta_inverse),
              predicate_delta_prime_value: bnToBnHex(
                predicate_get_delta_prime()
              ),
              tau_delta_intermediate_inverse: bnToBnHex(
                tau_delta_intermediate_inverse()
              ),
              tau_5_intermediate_inverse: bnToBnHex(
                tau_5_intermediate_inverse()
              ),
            };
          }),
        };
      }),
    };

    const data = `0x${sha256(JSON.stringify(vc.credentialSubject))}`;
    const rsv = ethUtil.fromRpcSig(vc.proof[0].proofValue);

    let contract;
    return NFTicket.deployed()
      .then((_contract) => {
        contract = _contract;
        return contract.flipSaleState.sendTransaction({
          from: accounts[0],
        });
      })
      .then((_result) => {
        assert.ok(_result);
      })
      .then(async () => {
        const receiptX = (
          await contract.mintTo.sendTransaction(
            accounts[0],
            1,
            verfiy_params,
            [
              vc.issuer.replace('did:lac:main:', ''),
              vc.credentialSubject.id.replace('did:lac:main:', ''),
              data,
              Math.round(moment(vc.issuanceDate).valueOf() / 1000),
              Math.round(moment(vc.expirationDate).valueOf() / 1000),
            ],
            rsv.v,
            rsv.r,
            rsv.s,
            {
              from: accounts[0],
              value: web3.utils.toWei('0.00041', 'ether'),
              gas: 299706180,
            }
          )
        ).receipt;
        console.log('Gas: ' + receiptX.gasUsed);
        const tokenId = receiptX.logs[0].args.tokenId;
        assert.equal(tokenId, '1', 'Token was not correctly minted');
      });
  });
});
