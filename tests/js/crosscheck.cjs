// Cross-implementation check: run the browser Covenant crypto (ui/covenant.js)
// under Node on deterministic inputs and emit results for the Python side to
// compare. Reads a JSON job from stdin, writes a JSON result to stdout.
//
// Job:    { password, a_hex, b_hex, server_frame }
// Result: { A, commit, pe, masked, shared, confirm_c, confirm_s,
//           client_mac, server_mac, js_client_frame, opened_server_frame }

const path = require("path");
const C = require(path.join(__dirname, "..", "..", "ui", "covenant.js"));

function readStdin() {
    return new Promise((resolve) => {
        let data = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (c) => (data += c));
        process.stdin.on("end", () => resolve(data));
    });
}

async function main() {
    const job = JSON.parse(await readStdin());
    const pw = C.enc(job.password);
    const a = BigInt("0x" + job.a_hex);
    const b = BigInt("0x" + job.b_hex);

    // Public elements.
    const A = C.modPow(C.G, a, C.P);
    const B = C.modPow(C.G, b, C.P);
    const commit = await C.sha1(C.bigToBytes(A, C.ELEMENT_BYTES));

    // Password element + masking + client-side unmask + shared secret.
    const pe = await C.secretToElement(pw);
    const masked = (B * pe) % C.P;
    const Brec = (masked * C.modinv(pe, C.P)) % C.P;
    const shared = C.modPow(Brec, a, C.P);

    const confirmC = await C.confirmMac(shared, commit, "client", A);
    const confirmS = await C.confirmMac(shared, commit, "server", B);
    const keys = await C.deriveKeys(shared);

    // Seal a client frame (for Python to open).
    const jsClientFrame = await C.seal(keys, 1, { text: "from-browser", sender: "browser" });

    // Open a Python-sealed server frame (round trip the other direction).
    const openedServerFrame = await C.open_(keys, 0, job.server_frame);

    const out = {
        A: C.bytesToHex(C.bigToBytes(A, C.ELEMENT_BYTES)),
        commit: C.bytesToHex(commit),
        pe: C.bytesToHex(C.bigToBytes(pe, C.ELEMENT_BYTES)),
        masked: C.bytesToHex(C.bigToBytes(masked, C.ELEMENT_BYTES)),
        shared: C.bytesToHex(C.bigToBytes(shared, C.ELEMENT_BYTES)),
        confirm_c: C.bytesToHex(confirmC),
        confirm_s: C.bytesToHex(confirmS),
        client_mac: C.bytesToHex(keys.client_mac),
        server_mac: C.bytesToHex(keys.server_mac),
        js_client_frame: jsClientFrame,
        opened_server_frame: openedServerFrame,
    };
    process.stdout.write(JSON.stringify(out));
}

main().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
