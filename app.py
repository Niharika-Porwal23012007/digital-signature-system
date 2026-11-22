import streamlit as st
from crypto_utils import compute_sha256, generate_keypair, sign_data, verify_data

st.set_page_config(
    page_title="Digital Signature Verification System",
    page_icon="🔐",
    layout="wide",
)

# Initialize session state
for key, default in {
    "private_pem": "",
    "public_pem": "",
    "last_message": "Confidential transaction: Transfer INR 25,000 to Account #4821.",
    "last_signature": "",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

st.title("🔐 Digital Signature Verification System")
st.caption(
    "Generate asymmetric key pairs, sign messages or files, and verify authenticity & integrity "
    "using RSA-PSS (SHA-256) or Ed25519."
)

with st.sidebar:
    st.header("How It Works")
    st.markdown(
        """
        1. **Key Generation**: Creates a linked Private Key (secret) & Public Key (shared).
        2. **Signing**: Hashes and signs data with the **Private Key**.
        3. **Verification**: Checks the signature using the **Public Key**.
        4. **Security Guarantees**:
           - **Authenticity**: Proves who signed it.
           - **Integrity**: Even a 1-character change invalidates the signature.
           - **Non-repudiation**: Signer cannot deny signing.
        """
    )
    st.info("All cryptographic operations run ephemerally in memory; keys are never stored on a database.")

tab1, tab2, tab3, tab4 = st.tabs(
    ["1. Key Pair Generator", "2. Sign Message / File", "3. Verify Signature", "4. Tamper Attack Demo"]
)

# ---------------- TAB 1: KEY GENERATOR ----------------
with tab1:
    st.subheader("Generate Asymmetric Key Pair")
    col_cfg1, col_cfg2, col_cfg3 = st.columns(3)

    with col_cfg1:
        algorithm = st.selectbox("Algorithm", ["RSA-PSS", "Ed25519"])
    with col_cfg2:
        rsa_size = st.selectbox(
            "RSA Key Size (bits)",
            [2048, 3072, 4096],
            disabled=(algorithm != "RSA-PSS"),
        )
    with col_cfg3:
        key_pass = st.text_input(
            "Private Key Passphrase (optional)",
            type="password",
            help="Encrypts the private key PEM with a passphrase.",
        )

    if st.button("Generate New Key Pair", type="primary", width="stretch"):
        priv_bytes, pub_bytes = generate_keypair(
            algorithm=algorithm,
            rsa_key_size=rsa_size,
            passphrase=key_pass or None,
        )
        st.session_state.private_pem = priv_bytes.decode("utf-8")
        st.session_state.public_pem = pub_bytes.decode("utf-8")
        st.success(f"{algorithm} key pair generated successfully!")

    if st.session_state.private_pem and st.session_state.public_pem:
        col_k1, col_k2 = st.columns(2)
        with col_k1:
            st.text_area("Private Key (Keep Secret!)", st.session_state.private_pem, height=260)
            st.download_button(
                "Download private_key.pem",
                data=st.session_state.private_pem,
                file_name="private_key.pem",
                mime="application/x-pem-file",
                width="stretch",
            )
        with col_k2:
            st.text_area("Public Key (Share Openly)", st.session_state.public_pem, height=260)
            st.download_button(
                "Download public_key.pem",
                data=st.session_state.public_pem,
                file_name="public_key.pem",
                mime="application/x-pem-file",
                width="stretch",
            )

# ---------------- TAB 2: SIGN ----------------
with tab2:
    st.subheader("Sign a Message or File")
    sign_mode = st.radio("Input Type", ["Text Message", "Upload File"], horizontal=True, key="sign_mode")

    data_to_sign = b""
    if sign_mode == "Text Message":
        msg_text = st.text_area(
            "Message to Sign",
            value=st.session_state.last_message,
            height=130,
            key="sign_msg_input",
        )
        data_to_sign = msg_text.encode("utf-8")
    else:
        uploaded_file = st.file_uploader("Upload any file to sign", key="sign_file_uploader")
        if uploaded_file is not None:
            data_to_sign = uploaded_file.getvalue()
            st.info(f"Loaded `{uploaded_file.name}` ({len(data_to_sign):,} bytes)")

    priv_input_mode = st.radio(
        "Private Key Source",
        ["Use Generated Key / Paste PEM", "Upload private_key.pem"],
        horizontal=True,
    )

    priv_pem_text = ""
    if priv_input_mode == "Use Generated Key / Paste PEM":
        priv_pem_text = st.text_area(
            "Private Key PEM",
            value=st.session_state.private_pem,
            height=180,
            key="sign_priv_pem",
        )
    else:
        priv_file = st.file_uploader("Upload Private Key (.pem)", type=["pem", "txt"], key="sign_priv_file")
        if priv_file is not None:
            priv_pem_text = priv_file.getvalue().decode("utf-8", errors="ignore")

    sign_pass = st.text_input("Private Key Passphrase (if encrypted)", type="password", key="sign_pass")

    if st.button("Generate Digital Signature", type="primary", width="stretch"):
        if not data_to_sign:
            st.error("Please enter a message or upload a file first.")
        elif not priv_pem_text.strip():
            st.error("Please provide a valid Private Key PEM (generate one in Tab 1 if needed).")
        else:
            try:
                result = sign_data(
                    data=data_to_sign,
                    private_key_pem=priv_pem_text.encode("utf-8"),
                    passphrase=sign_pass or None,
                )
                if sign_mode == "Text Message":
                    st.session_state.last_message = msg_text
                st.session_state.last_signature = result["signature_b64"]

                st.success(f"Signed using **{result['algorithm']}**")
                st.code(f"SHA-256 Digest: {result['sha256']}", language="text")
                st.text_area("Digital Signature (Base64)", result["signature_b64"], height=120)
                st.download_button(
                    "Download signature.sig",
                    data=result["signature_b64"],
                    file_name="signature.sig",
                    mime="text/plain",
                    width="stretch",
                )
            except Exception as exc:
                st.error(f"Signing failed: {exc}")

# ---------------- TAB 3: VERIFY ----------------
with tab3:
    st.subheader("Verify Digital Signature")
    verify_mode = st.radio("Input Type", ["Text Message", "Upload File"], horizontal=True, key="verify_mode")

    data_to_verify = b""
    if verify_mode == "Text Message":
        verify_msg = st.text_area(
            "Original Message",
            value=st.session_state.last_message,
            height=130,
            key="verify_msg_input",
        )
        data_to_verify = verify_msg.encode("utf-8")
    else:
        v_file = st.file_uploader("Upload file to verify", key="verify_file_uploader")
        if v_file is not None:
            data_to_verify = v_file.getvalue()
            st.info(f"Loaded `{v_file.name}` ({len(data_to_verify):,} bytes)")

    sig_input = st.text_area(
        "Digital Signature (Base64)",
        value=st.session_state.last_signature,
        height=110,
        key="verify_sig_input",
    )

    pub_input_mode = st.radio(
        "Public Key Source",
        ["Use Generated Key / Paste PEM", "Upload public_key.pem"],
        horizontal=True,
    )
    pub_pem_text = ""
    if pub_input_mode == "Use Generated Key / Paste PEM":
        pub_pem_text = st.text_area(
            "Public Key PEM",
            value=st.session_state.public_pem,
            height=180,
            key="verify_pub_pem",
        )
    else:
        pub_file = st.file_uploader("Upload Public Key (.pem)", type=["pem", "txt"], key="verify_pub_file")
        if pub_file is not None:
            pub_pem_text = pub_file.getvalue().decode("utf-8", errors="ignore")

    if st.button("Verify Signature", type="primary", width="stretch"):
        if not data_to_verify:
            st.error("Please provide the message or file to verify.")
        elif not sig_input.strip() or not pub_pem_text.strip():
            st.error("Please provide both the Digital Signature and the Public Key PEM.")
        else:
            is_valid, algo, status = verify_data(
                data=data_to_verify,
                signature_b64=sig_input,
                public_key_pem=pub_pem_text.encode("utf-8"),
            )
            st.code(f"Computed SHA-256: {compute_sha256(data_to_verify)}", language="text")
            if is_valid:
                st.success(f"✅ {status} ({algo})")
            else:
                st.error(f"❌ {status} ({algo})")

# ---------------- TAB 4: TAMPER DEMO ----------------
with tab4:
    st.subheader("Interactive Tamper Detection Simulation")
    st.write(
        "See how even a tiny modification (e.g., changing one digit in an amount) breaks cryptographic verification."
    )

    original_text = st.text_input(
        "1. Original Signed Message",
        value="Pay Alice INR 1000 on 2026-11-22",
    )
    tampered_text = st.text_input(
        "2. Attacker-Modified Message",
        value="Pay Alice INR 9000 on 2026-11-22",
    )

    if st.button("Run Live Tamper Simulation (Ed25519)", type="primary", width="stretch"):
        priv_pem, pub_pem = generate_keypair("Ed25519")
        signed = sign_data(original_text.encode("utf-8"), priv_pem)

        ok_orig, _, msg_orig = verify_data(original_text.encode("utf-8"), signed["signature_b64"], pub_pem)
        ok_tamp, _, msg_tamp = verify_data(tampered_text.encode("utf-8"), signed["signature_b64"], pub_pem)

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Original Message Check**")
            st.code(f"SHA-256: {compute_sha256(original_text.encode('utf-8'))}")
            if ok_orig:
                st.success(f"✅ {msg_orig}")
        with c2:
            st.markdown("**Tampered Message Check**")
            st.code(f"SHA-256: {compute_sha256(tampered_text.encode('utf-8'))}")
            if not ok_tamp:
                st.error(f"❌ {msg_tamp}")
            else:
                st.warning("Both messages are identical, so the signature still matches!")
