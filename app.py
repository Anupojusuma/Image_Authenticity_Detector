import streamlit as st
import exifread
import pandas as pd
import hashlib
import datetime
import numpy as np
import cv2
from PIL import Image, ImageChops, ImageEnhance
import io

# ----------------------------------------------------
# PAGE CONFIG
# ----------------------------------------------------

st.set_page_config(page_title="Image Authenticity Detector", layout="wide")

# ----------------------------------------------------
# CUSTOM CSS
# ----------------------------------------------------

st.markdown("""
<style>
.stApp {
    background-color: #0E1117;
}

h1, h2, h3 {
    color: #FAFAFA;
}

[data-testid="stMetric"] {
    background-color: #1E222B;
    padding: 15px;
    border-radius: 10px;
}

footer {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)

# ----------------------------------------------------
# HEADER
# ----------------------------------------------------

st.title("📷 Image Authenticity Detector")
st.write("Detect manipulated or AI-generated images using forensic analysis.")

# ----------------------------------------------------
# SIDEBAR
# ----------------------------------------------------

st.sidebar.title("Upload Image")
uploaded_file = st.sidebar.file_uploader(
    "Choose an image",
    type=["jpg", "jpeg", "png"]
)

st.sidebar.markdown("---")
st.sidebar.write("Supported checks:")
st.sidebar.write("• Metadata Analysis")
st.sidebar.write("• Editing Software Detection")
st.sidebar.write("• SHA256 Integrity")
st.sidebar.write("• Error Level Analysis")
st.sidebar.write("• Noise Level Analysis")

# ----------------------------------------------------
# WHEN IMAGE IS UPLOADED
# ----------------------------------------------------

if uploaded_file is not None:

    authenticity_score = 0
    risk_flags = []

    # ----------------------------------------------------
    # LAYOUT
    # ----------------------------------------------------

    col1, col2 = st.columns([1,1])

    with col1:
        st.image(uploaded_file, caption="Uploaded Image", width=400)

    # ----------------------------------------------------
    # EXIF METADATA
    # ----------------------------------------------------

    uploaded_file.seek(0)
    tags = exifread.process_file(uploaded_file)

    metadata_data = []

    if tags:

        authenticity_score += 30
        risk_flags.append("EXIF metadata present")

        for tag, value in tags.items():
            metadata_data.append([tag, str(value)])

        df = pd.DataFrame(metadata_data, columns=["Metadata Tag", "Value"])

    else:

        authenticity_score -= 20
        risk_flags.append("Missing EXIF metadata")

    # ----------------------------------------------------
    # AUTHENTICITY CHECKS
    # ----------------------------------------------------

    camera_model = tags.get("Image Model")

    if camera_model:
        authenticity_score += 20
        risk_flags.append("Camera metadata detected")

    else:
        authenticity_score -= 10
        risk_flags.append("Missing camera model")

    software_tag = tags.get("Image Software")

    if software_tag:

        software_value = str(software_tag).lower()

        suspicious_tools = [
            "photoshop","gimp","lightroom","snapseed",
            "picsart","canva","pixlr","fotor"
        ]

        if any(tool in software_value for tool in suspicious_tools):

            authenticity_score -= 40
            risk_flags.append(f"Editing software detected ({software_tag})")

        else:
            authenticity_score += 10

    else:
        authenticity_score -= 5
        risk_flags.append("Software metadata missing")

    date_tag = tags.get("EXIF DateTimeOriginal") or tags.get("Image DateTime")

    if date_tag:

        try:
            date_str = str(date_tag)
            datetime.datetime.strptime(date_str,"%Y:%m:%d %H:%M:%S")
            authenticity_score += 10

        except:
            authenticity_score -= 20
            risk_flags.append("Invalid timestamp format")

    else:
        risk_flags.append("Missing timestamp metadata")

    # ----------------------------------------------------
    # HASH
    # ----------------------------------------------------

    uploaded_file.seek(0)
    file_bytes = uploaded_file.read()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    # ----------------------------------------------------
    # ELA
    # ----------------------------------------------------

    uploaded_file.seek(0)
    image = Image.open(uploaded_file).convert("RGB")

    temp_buffer = io.BytesIO()
    image.save(temp_buffer, format="JPEG", quality=90)

    temp_buffer.seek(0)
    compressed_image = Image.open(temp_buffer)

    ela_image = ImageChops.difference(image, compressed_image)

    extrema = ela_image.getextrema()
    max_diff = max([ex[1] for ex in extrema])

    if max_diff == 0:
        max_diff = 1

    scale = 255.0 / max_diff
    ela_image = ImageEnhance.Brightness(ela_image).enhance(scale)

    ela_array = np.array(ela_image)
    ela_mean = ela_array.mean()

    if ela_mean < 5:
        authenticity_score += 10

    elif ela_mean >= 20:
        authenticity_score -= 20
        risk_flags.append("Compression anomalies detected")

    # ----------------------------------------------------
    # NOISE ANALYSIS
    # ----------------------------------------------------

    uploaded_file.seek(0)

    file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
    gray_image = cv2.imdecode(file_bytes, cv2.IMREAD_GRAYSCALE)

    noise_variance = cv2.Laplacian(gray_image, cv2.CV_64F).var()

    if noise_variance < 20:

        authenticity_score -= 20
        risk_flags.append("Very low sensor noise")

    elif noise_variance > 80:

        authenticity_score += 10

    # ----------------------------------------------------
    # SCORE PANEL
    # ----------------------------------------------------

    with col2:

        final_score = max(0, min(100, authenticity_score))

        st.metric("Authenticity Score", f"{final_score}/100")

        st.progress(final_score / 100)

        if final_score > 80:
            st.success("Image likely ORIGINAL")

        elif final_score > 50:
            st.warning("Some suspicious indicators detected")

        else:
            st.error("Image likely EDITED or AI-generated")

    # ----------------------------------------------------
    # TABS
    # ----------------------------------------------------

    tab1, tab2, tab3 = st.tabs([
        "Metadata",
        "Forensic Analysis",
        "Integrity"
    ])

    # ----------------------------------------------------
    # METADATA TAB
    # ----------------------------------------------------

    with tab1:

        if tags:
            with st.expander("View EXIF Metadata"):
                st.dataframe(df, use_container_width=True)
        else:
            st.warning("No metadata found")

    # ----------------------------------------------------
    # FORENSIC TAB
    # ----------------------------------------------------

    with tab2:

        colA, colB = st.columns(2)

        with colA:
            st.subheader("ELA Visualization")
            st.image(ela_image)

            st.write(f"ELA Mean Intensity: {ela_mean:.2f}")

        with colB:
            st.subheader("Noise Analysis")

            st.write(f"Noise Variance: {noise_variance:.2f}")

            if noise_variance < 20:
                st.warning("Very low noise detected")

            elif noise_variance < 80:
                st.info("Moderate noise detected")

            else:
                st.success("Natural camera noise detected")

    # ----------------------------------------------------
    # INTEGRITY TAB
    # ----------------------------------------------------

    with tab3:

        st.subheader("SHA256 Hash")

        st.code(sha256_hash)

        st.subheader("Risk Indicators")

        if len(risk_flags) == 0:
            st.success("No suspicious indicators detected")

        else:
            for flag in risk_flags:
                st.write("•", flag)

# ----------------------------------------------------
# FOOTER
# ----------------------------------------------------

st.markdown("---")
st.caption("Image Authenticity Detector • Built with Python & Streamlit")