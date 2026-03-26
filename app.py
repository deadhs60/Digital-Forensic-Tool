import streamlit as st
import os
import pandas as pd

from analyzer.file_analyzer import analyze_file
from analyzer.hash_checker import calculate_hash
from analyzer.properties import file_properties
from analyzer.metadata import get_metadata
from analyzer.extractor import extract_strings

from reports.report_generator import generate_report
from analyzer.browser_history import (
    extract_history,
    get_top_sites,
    search_history,
    detect_suspicious,
    timeline_data
)

import matplotlib.pyplot as plt

st.markdown("<h1 style='text-align: center;'>Digital Forensics Investigation Tool</h1>", unsafe_allow_html=True)

st.set_page_config(page_title="Digital Forensics Tool", layout="wide")

# =========================
# FILE FORENSICS SECTION
# =========================
st.header("File Forensics")

uploaded_file = st.file_uploader("Upload Evidence File")

if uploaded_file:
    os.makedirs("temp", exist_ok=True)
    file_path = os.path.join("temp", uploaded_file.name)

    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())

    st.success("File Uploaded Successfully")

    result = analyze_file(file_path)
    hash_value = calculate_hash(file_path)
    fileProperty =  file_properties(file_path)
    metadata = get_metadata(file_path)
    strings = extract_strings(file_path)

    # =========================
    # BASIC INFORMATION
    # =========================
    st.subheader("File Information")
    st.write(result)

    # =========================
    # HASHES
    # =========================
    st.subheader("File Hashes")
    st.json(hash_value)

    # =========================
    # PROPERTIES
    # =========================
    st.subheader("File Properties")
    st.json(fileProperty)

    # =========================
    # METADATA
    # =========================
    st.subheader("Metadata")
    st.json(metadata)

    # =========================
    # STRINGS EXTRACTOR
    # =========================
    st.subheader("Extracted Strings")
    df_strings = pd.DataFrame(strings, columns=["Extracted Strings"])
    st.dataframe(df_strings)


    # =========================
    # REPORT
    # =========================
    full_data = {
        "File Information": result,
        "Hash": hash_value,
        "File Properties": fileProperty,
        "Metadata": metadata,
        "Extracted Strings": strings  # limit
    }

    #st.subheader("Forensic Report")
    #st.json(full_data)

    if st.button("Generate Report"):
        report_file = generate_report(full_data)

        with open(report_file, "rb") as f:
            st.download_button(
                label="Download Report",
                data=f,
                file_name="forensic_report.pdf",
                mime="application/pdf"
            )

# =========================
# BROWSER HISTORY ANALYSIS
# =========================

st.header("Browser History Analysis")

history_file = st.file_uploader("Upload Chrome History DB", key="history")

if history_file:
    with open("history.db", "wb") as f:
        f.write(history_file.read())

    df = extract_history("history.db")

    if isinstance(df, str):
        st.error(df)
    else:
        st.success("History Loaded Successfully")

        # Full History
        st.subheader("Full History")
        st.dataframe(df)

        # Search
        st.subheader("Search History")
        keyword = st.text_input("Enter keyword")

        if keyword:
            filtered = search_history(df, keyword)
            st.dataframe(filtered)

        # Top Sites
        st.subheader("Top Visited Sites")
        top_sites = get_top_sites(df)
        st.dataframe(top_sites)

        plt.figure()
        plt.bar(top_sites["url"][:5], top_sites["visit_count"][:5])
        plt.xticks(rotation=45)
        st.pyplot(plt)

        # Suspicious
        st.subheader("Suspicious Activity")
        suspicious = detect_suspicious(df)

        if suspicious:
            for s in suspicious:
                st.warning(f"Suspicious: {s}")
        else:
            st.success("No suspicious activity detected")

        # Timeline
        st.subheader("Timeline Analysis")
        timeline = timeline_data(df)

        st.dataframe(timeline)

        plt.figure()
        plt.plot(timeline["date"], timeline["visits"])
        plt.xticks(rotation=45)
        st.pyplot(plt)