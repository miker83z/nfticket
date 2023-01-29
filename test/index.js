const fs = require('fs');
const Web3 = require('web3');
const BN = Web3.utils.BN;

const NFTicket = artifacts.require('NFTicket');

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
  it('test_verify_predicate_proof_NFT_mint', () => {
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
          await contract.mintTo.sendTransaction(accounts[0], 1, verfiy_params, {
            from: accounts[0],
            value: web3.utils.toWei('0.00041', 'ether'),
            gas: 299706180,
          })
        ).receipt;
        console.log('Gas: ' + receiptX.gasUsed);
        const tokenId = receiptX.logs[0].args.tokenId;
        assert.equal(tokenId, '1', 'Token was not correctly minted');
      });
  });
});
