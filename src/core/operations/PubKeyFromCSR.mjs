import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import forge from "node-forge";

const { asn1, util } = forge;

/**
 * Extracts public keys from Certificate Signing Requests (CSR).
 * Supports RSA and EC keys via ASN.1 parsing.
 */
class PubKeyFromCSR extends Operation {

    /**
     * PubKeyFromCSR constructor
     */
    constructor() {
        super();

        this.name = "Public Key from CSR";
        this.module = "PublicKey";
        this.description =
            "Extracts the Public Key from a CSR. Supports RSA and EC.";
        this.infoURL =
            "https://en.wikipedia.org/wiki/Certificate_signing_request";

        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
        this.checks = [];
    }

    /**
     * Extract public key(s) from CSR PEM input
     *
     * @param {string} input - PEM encoded CSR(s)
     * @returns {string} PEM encoded public key(s)
     */
    run(input) {
        if (!input || typeof input !== "string") return "";

        const BEGIN = "-----BEGIN CERTIFICATE REQUEST-----";
        const END = "-----END CERTIFICATE REQUEST-----";

        if (input.includes(BEGIN) && !input.includes(END)) {
            throw new OperationError(
                `CSR footer '${END}' not found`
            );
        }

        const matches = [
            ...input.matchAll(
                /-----BEGIN CERTIFICATE REQUEST-----[\s\S]*?-----END CERTIFICATE REQUEST-----/g
            )
        ];

        if (matches.length === 0) return "";

        const outputs = [];

        for (const match of matches) {
            const csrPem = match[0];

            try {
                const base64 = csrPem
                    .replace(BEGIN, "")
                    .replace(END, "")
                    .replace(/\s+/g, "");

                const der = util.decode64(base64);
                const obj = asn1.fromDer(der);

                const cri = obj.value[0];
                const spki = cri.value[2];

                const spkiDer = asn1.toDer(spki).getBytes();
                const spkiB64 = util.encode64(spkiDer);

                const pubKeyPem =
                    "-----BEGIN PUBLIC KEY-----\n" +
                    spkiB64.match(/.{1,64}/g).join("\n") +
                    "\n-----END PUBLIC KEY-----";

                outputs.push(pubKeyPem);

            } catch (e) {
                throw new OperationError(
                    `Failed to parse CSR or extract public key: ${e}`
                );
            }
        }

        return outputs.join("");
    }
}

export default PubKeyFromCSR;
