import streamlit as st
import pandas as pd
import time
import re
from urllib.parse import urlparse

import logging

from utils.styles import load_custom_font
from utils.predictor import predict_url, probe_url

def _normalize_host(raw_input: str) -> str:
    cleaned = raw_input.strip()
    cleaned = re.sub(r'^(https?://)', '', cleaned, flags=re.IGNORECASE)
    return cleaned

def _normalize_host_input():
    st.session_state["website_url"] = _normalize_host(st.session_state.get("website_url", ""))

st.set_page_config(
    page_title="URL Detection", 
    page_icon="URL", 
    layout="centered",
    initial_sidebar_state="auto",
    menu_items={
        'About': "This application uses AI to detect phishing emails and URLs."
    })

load_custom_font()


# Custom CSS
st.markdown("""
    <style>
    .url-safe {
        background: linear-gradient(135deg, #00C851 0%, #007E33 100%);
        padding: 2rem;
        margin-bottom: 10px!important;
        border-radius: 15px;
        text-align: center;
    }
    .url-phishing {
        background: #cc0000;/*#ff4444;*/
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 10px!important;
        text-align: center;
        animation: shake 0.5s;
    }
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-10px); }
        75% { transform: translateX(10px); }
    }
    .feature-card {
        background: #141414;
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
    }
    </style>
""", unsafe_allow_html=True)

st.title("URL Phishing Detection")
st.markdown("Check if a website is safe to visit using live reputation scoring from the URL service.")

# Main tabs
tab1, tab2 = st.tabs(["Single URL Check", "Batch URL Analysis"])


def _render_reachability_summary(reachability: dict):
    reach_status = "Reachable" if reachability.get('reachable') else "Unreachable"
    status_code = reachability.get('status_code')
    response_time = reachability.get('response_time_ms')
    final_url = reachability.get('final_url')
    redirects = reachability.get('redirects') or []
    tls_status = reachability.get('tls_valid')
    tls_text = "Valid" if tls_status else ("Invalid" if tls_status is False else "Unknown")

    reach_col1, reach_col2, reach_col3 = st.columns(3)
    with reach_col1:
        st.metric("Reachability", reach_status)
        st.metric("HTTP Status", f"{status_code}" if status_code else "N/A")
    with reach_col2:
        st.metric("Response Time", f"{response_time} ms" if response_time else "N/A")
        st.metric("TLS Status", tls_text)
    with reach_col3:
        st.metric("Final URL", final_url or "N/A")
        st.metric("Redirects", f"{len(redirects)} hops" if redirects else "0 hops")

    if reachability.get('status_message'):
        st.caption(f"Server message: {reachability.get('status_message')}")
    if redirects or final_url:
        chain = redirects + ([final_url] if final_url else [])
        st.caption(f"Redirect chain: {' ➝ '.join(chain)}")
    if reachability.get('error'):
        st.warning(f"Reachability error: {reachability.get('error')}")

with tab1:
    st.markdown("#### Enter URL to Analyze")
    
    scheme_col, url_col = st.columns([0.7, 3])
    with scheme_col:
        scheme = st.selectbox("Scheme", ["https://", "http://"], index=0, help="Select the protocol to prefix the hostname.")
    if "website_url" not in st.session_state:
        st.session_state["website_url"] = ""
    with url_col:
        st.text_input(
            "Website URL",
            placeholder="example.com",
            help="Enter the hostname without the protocol.",
            key="website_url",
            on_change=_normalize_host_input
        )
    normalized_host = st.session_state.get("website_url", "")
    url_input = f"{scheme}{normalized_host}" if normalized_host else ""
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        check_btn = st.button("Check URL", type="primary", use_container_width=True)
    with col2:
        st.button("Clear", use_container_width=True)
    
    if check_btn:
        if not url_input:
            st.error("Please enter a URL to analyze!")
        elif not url_input.startswith(('http://', 'https://')):
            st.warning("URL should start with http:// or https://")
        else:
            spinner = st.spinner("Analyzing URL...")
            spinner.__enter__()
            spinner_active = True
            try:
                parsed = urlparse(url_input)
                domain = parsed.netloc

                reachability = probe_url(url_input)
                if not reachability.get('reachable'):
                    spinner.__exit__(None, None, None)
                    spinner_active = False
                    st.warning(
                        "Hostname is not reachable; ensure the domain resolves and responds before re-running the check."
                    )
                    _render_reachability_summary(reachability)
                    st.stop()

                try:
                    result = predict_url(url_input, reachability=reachability)
                    model_label = result.get('label', 'benign').lower()
                    confidence = float(result.get('confidence', 0.0))
                    reachability = result.get('reachability', reachability)
                except Exception:
                    logging.exception("URL prediction failed")
                    st.error("URL prediction failed. Please try again shortly.")
                    st.stop()
            finally:
                if spinner_active:
                    spinner.__exit__(None, None, None)

            is_phishing = model_label != 'benign'
            displayed_label = model_label.replace('_', ' ').title()

            st.markdown("---")
            st.markdown("#### URL Analysis Results")
            
            # Main result
            if is_phishing:
                st.markdown("""
                    <h4 class="url-phishing">
                        Dangerous Website Detected
                    </h4>
                """, unsafe_allow_html=True)
                st.error("This URL shows multiple phishing indicators. Do not visit!")
                try:
                    st.info(f"Prediction: {displayed_label}")
                except Exception:
                    pass
            else:
                st.markdown("""
                    <h4 class="url-safe">
                        URL Appears Safe
                    </h4>
                """, unsafe_allow_html=True)
                st.success("This website appears to be legitimate and safe to visit.")
                try:
                    st.info(f"Prediction: {displayed_label}")
                except Exception:
                    pass
            
            # Confidence meter
            # st.markdown("#### Confidence Score")
            # confidence_col1, confidence_col2 = st.columns([3, 1])
            # with confidence_col1:
            #     st.progress(confidence)
            # with confidence_col2:
            #     st.metric("Confidence", f"{confidence * 100:.1f}%")
            
            # URL breakdown
            st.markdown("#### URL Component Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("##### URL Components")
                components = pd.DataFrame({
                    'Component': ['Protocol', 'Domain', 'Path', 'Full URL'],
                    'Value': [
                        parsed.scheme,
                        domain,
                        parsed.path if parsed.path else '/',
                        url_input[:50] + '...' if len(url_input) > 50 else url_input
                    ]
                })
                st.dataframe(components, use_container_width=True, hide_index=True)
                
                # Security features
                st.markdown("##### Security Features")
                security_features = []
                
                if parsed.scheme == 'https':
                    security_features.append("HTTPS Encryption")
                else:
                    security_features.append("No HTTPS (Insecure)")
                
                if len(domain.split('.')) <= 3:
                    security_features.append("Normal domain structure")
                else:
                    security_features.append("Multiple subdomains detected")
                
                # Check for IP address
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                    security_features.append("IP address instead of domain")
                else:
                    security_features.append("Proper domain name")
                
                for feature in security_features:
                    st.markdown(f"<div class='feature-card'>{feature}</div>", unsafe_allow_html=True)
            
            with col2:
                st.markdown("##### Risk Indicators")
                
                risk_indicators = []
                risk_score = 0
                
                # Check for suspicious patterns
                if parsed.scheme == 'http':
                    risk_indicators.append("No SSL/TLS encryption")
                    risk_score += 30
                
                suspicious_keywords = ['verify', 'account', 'login', 'secure', 'update', 'confirm']
                if any(keyword in url_input.lower() for keyword in suspicious_keywords):
                    risk_indicators.append("Suspicious keywords in URL")
                    risk_score += 25
                
                if len(parsed.path) > 50:
                    risk_indicators.append("Unusually long URL path")
                    risk_score += 15
                
                if domain.count('.') > 2:
                    risk_indicators.append("Multiple subdomains")
                    risk_score += 20
                
                if '@' in url_input:
                    risk_indicators.append("Contains @ symbol (phishing technique)")
                    risk_score += 35
                
                if len(domain) > 30:
                    risk_indicators.append("Unusually long domain name")
                    risk_score += 10

                if risk_indicators:
                    for indicator in risk_indicators:
                        st.markdown(f"<div class='feature-card'>{indicator}</div>", unsafe_allow_html=True)
                    
                    st.markdown(f"**Total Risk Score: {risk_score}/100**")
                    st.progress(risk_score / 100)
                else:
                    st.markdown("<div class='feature-card'>No significant risk indicators found</div>", unsafe_allow_html=True)
                    st.markdown("**Total Risk Score: 0/100**")
                    st.progress(0.0)
            
            # URL Features Summary
            st.markdown("\n#### Feature Analysis Summary", unsafe_allow_html=True)
            
            feature_col1, feature_col2, feature_col3, feature_col4 = st.columns(4)
            
            with feature_col1:
                st.metric("URL Length", f"{len(url_input)} chars")
            with feature_col2:
                st.metric("Domain Length", f"{len(domain)} chars")
            with feature_col3:
                st.metric("Subdomain Count", len(domain.split('.')) - 1)
            with feature_col4:
                st.metric("Special Chars", url_input.count('-') + url_input.count('_'))
            
            # Recommendations
            st.markdown("#### Recommendations")
            
            if is_phishing:
                st.error("""
                **Security Warning:**
                - Do not visit this website
                - Do not enter any personal information
                - Do not download anything from this site
                - Report this URL to your security team
                - Run a security scan if you visited this site
                """)
            else:
                st.info("""
                **Safety Tips:**
                - Always verify you're on the correct website
                - Check for HTTPS and valid SSL certificate
                - Look for trust indicators (padlock icon, company info)
                - Be cautious with links from emails or messages
                - Use bookmarks for frequently visited sites
                """)
            
            # Additional Info
            # with st.expander("Technical Details"):
            #     st.json({
            #         "url": url_input,
            #         "protocol": parsed.scheme,
            #         "domain": domain,
            #         "path": parsed.path,
            #         "query": parsed.query if parsed.query else "None",
            #         "has_https": parsed.scheme == "https",
            #         "subdomain_count": len(domain.split('.')) - 1,
            #         "url_length": len(url_input),
            #         "prediction": "Phishing" if is_phishing else "Safe",
            #         # "confidence": f"{confidence * 100:.2f}%"
            #     })

with tab2:
    st.markdown("### Batch URL Analysis")
    st.info("Upload a text file or CSV with multiple URLs for bulk checking")
    
    # Sample data
    st.markdown("**Expected Format:**")
    st.code("https://example1.com\nhttps://example2.com\nhttps://example3.com", language="text")
    
    # URL input methods
    input_method = st.radio("Choose input method:", ["Upload File", "Paste URLs"])
    
    urls_to_check = []
    
    if input_method == "Upload File":
        uploaded_file = st.file_uploader(
            "Upload file with URLs",
            type=['txt', 'csv'],
            help="One URL per line"
        )
        
        if uploaded_file:
            content = uploaded_file.read().decode('utf-8')
            urls_to_check = [line.strip() for line in content.split('\n') if line.strip()]
            st.success(f"Loaded {len(urls_to_check)} URLs")
    
    else:
        urls_text = st.text_area(
            "Paste URLs (one per line)",
            height=200,
            placeholder="https://example1.com\nhttps://example2.com\nhttps://example3.com"
        )
        if urls_text:
            urls_to_check = [line.strip() for line in urls_text.split('\n') if line.strip()]
    
    if urls_to_check:
        st.info(f"Ready to analyze {len(urls_to_check)} URLs")
        
        if st.button("Analyze All URLs", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            errors = []
            
            for i, url in enumerate(urls_to_check):
                progress_bar.progress((i + 1) / len(urls_to_check))
                status_text.text(f"Analyzing URL {i + 1} of {len(urls_to_check)}...")
                
                if not url.startswith(('http://', 'https://')):
                    errors.append(f"Skipping invalid URL: {url}")
                    results.append({
                        'URL': url,
                        'Status': 'Invalid',
                        'Confidence': '0.0%',
                        'Risk Level': 'Unknown'
                    })
                    continue

                try:
                    prediction = predict_url(url)
                    label = prediction.get('label', 'benign').lower()
                    confidence = float(prediction.get('confidence', 0.0))
                    reachability = prediction.get('reachability', {})
                except Exception:
                    logging.exception("Batch URL prediction failed")
                    errors.append(f"Failed to classify {url}")
                    label = 'unknown'
                    confidence = 0.0
                    reachability = {}

                is_phishing = label != 'benign'
                reachable = reachability.get('reachable', True)
                if not reachable:
                    status = 'Unreachable'
                    risk_level = 'Unknown'
                else:
                    status = 'Phishing' if is_phishing else 'Safe'
                    if label == 'unknown':
                        status = 'Error'
                    risk_level = 'High' if is_phishing else 'Low'

                results.append({
                    'URL': url[:50] + '...' if len(url) > 50 else url,
                    'Status': status,
                    'Prediction Label': label.replace('_', ' ').title(),
                    'Reachability': 'Reachable' if reachable else 'Unreachable',
                    # 'Confidence': f"{confidence * 100:.1f}%",
                    'Risk Level': risk_level
                })

            st.success(f"Analysis complete! Processed {len(urls_to_check)} URLs")

            if errors:
                with st.expander("Issues encountered"):
                    for err in errors:
                        st.warning(err)

            results_df = pd.DataFrame(results)
            st.dataframe(results_df, use_container_width=True, hide_index=True)

            phishing_count = sum(1 for r in results if r['Status'] == 'Phishing')
            safe_count = sum(1 for r in results if r['Status'] == 'Safe')
            error_count = len(results) - phishing_count - safe_count

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total URLs", len(results))
            with col2:
                st.metric("Phishing Detected", phishing_count)
            with col3:
                st.metric("Safe URLs", safe_count)

            if error_count:
                st.caption(f"{error_count} entries failed to predict")

            csv = results_df.to_csv(index=False)
            st.download_button(
                label="Download Results (CSV)",
                data=csv,
                file_name="url_analysis_results.csv",
                mime="text/csv"
            )

# Sidebar
# with st.sidebar:
#     st.markdown("### Common URL Phishing Signs")
#     st.markdown("""
#     - Using HTTP instead of HTTPS
#     - Misspelled domain names
#     - Excessive subdomains
#     - Suspicious TLDs (.tk, .ml, .ga)
#     - URLs with @ symbols
#     - Shortened/obfuscated URLs
#     - URLs with IP addresses
#     """)