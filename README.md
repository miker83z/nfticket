# NFTicket

Proof-of-concept implementation of a NFT that performs an [Anonymous Credentials Verification](https://github.com/robmuth/eth-ac-verifier) before minting a Ticket.

## Truffle Suite Test Case

```
truffle test --network ganache
```

Expected output:

```

  Contract: NFTicket
Gas: 84338171
    ✔ test_verify_predicate_proof_NFT_mint (6778ms)


  1 passing (7s)
```

## License

[Apache License 2.0](LICENSE).

### Contributions

- Hyperledger Ursa: [Apache 2.0](https://github.com/hyperledger/ursa/blob/main/LICENSE)
- firoorg/solidity-BigNumber: [MIT](https://github.com/firoorg/solidity-BigNumber/blob/master/LICENSE)
- robmuth/eth-ac-verifier: [Apache 2.0](https://github.com/robmuth/eth-ac-verifier/blob/master/LICENSE)
