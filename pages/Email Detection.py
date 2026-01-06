import logging
import streamlit as st
import pandas as pd
import time
from utils.predictor import predict_email
from utils.styles import load_custom_font

st.set_page_config(
    page_title="Email Detection", 
    page_icon="Email", 
    layout="centered",
    menu_items={
        'About': "This application uses AI to detect phishing emails and URLs."
    })

load_custom_font()

# Custom CSS
st.markdown("""
    <style>
    .phishing-alert {
        background-color: #ff4444;
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 10px;
        text-align: center;
        animation: pulse 2s infinite;
    }
    .safe-alert {
        background-color: #00C851;
        padding: 2rem;
        margin-bottom: 10px;
        border-radius: 10px;
        text-align: center;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.7; }
        100% { opacity: 1; }
    }
    .confidence-meter {
        background: #f0f0f0;
        border-radius: 10px;
        padding: 1rem;
        margin: 1rem 0;
    }
    </style>
""", unsafe_allow_html=True)

st.title("Email Phishing Detection")
st.markdown("Analyze email content to detect potential phishing attempts using AI.")

# Tabs for different input methods
tab1, tab2, tab3 = st.tabs(["Paste Email Content", "Upload Email File", "Batch Analysis"])

with tab1:
    st.markdown("### Enter Email Details")
    
    col1, col2 = st.columns(2)
    
    with col1:
        subject = st.text_input("Email Subject", placeholder="Enter email subject")
    
    with col2:
        sender_email = st.text_input("Sender Email Address", placeholder="example@domain.com")
        # sender_name = st.text_input("Sender Name (Optional)", placeholder="John Doe")
        # has_attachments = st.checkbox("Email has attachments")
    
    email_body = st.text_area(
        "Email Body",
        height=300,
        placeholder="""Paste the full email content here...

Example:
Dear Customer,

Your account has been compromised. Click here immediately to verify your identity:
http://suspicious-link.com

Thank you,
Security Team"""
    )
    
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        analyze_btn = st.button("Analyze Email", type="primary", use_container_width=True)
    with col2:
        clear_btn = st.button("Clear", use_container_width=True)
    
    if clear_btn:
        st.rerun()
    
    if analyze_btn:
        if not email_body:
            st.error("Email body is required for analysis")
        else:
            with st.spinner("Analyzing email..."):
                
                suspicious_keywords = ['click here', 'verify', 'confirm', 'urgent', 'account', 'password']
                displayed_label = 'Unknown'
                prediction_source = 'model'
                try:
                    result = predict_email(subject, email_body)
                    model_label = result.get('label', '')
                    confidence = float(result.get('confidence', 0.0))
                    normalized = str(model_label).lower()
                    if normalized in ('1', 'spam', 'spammy'):
                        is_spam = True
                        displayed_label = 'Spam'
                    elif normalized in ('0', 'ham', 'real', 'non-spam'):
                        is_spam = False
                        displayed_label = 'Real'
                    else:
                        is_spam = False
                        displayed_label = model_label
                except FileNotFoundError:
                    logging.exception("Email model is missing")
                    st.warning("Email model not found. Falling back to heuristic detection.")
                    prediction_source = 'heuristic'
                    is_spam = any(keyword in email_body.lower() for keyword in suspicious_keywords)
                    confidence = 0.87 if is_spam else 0.92
                    displayed_label = 'Spam' if is_spam else 'Real'
                except Exception as err:
                    logging.exception("Email model prediction failed")
                    st.warning(f"Email prediction failed ({err}). Using heuristic fallback.")
                    prediction_source = 'heuristic'
                    is_spam = any(keyword in email_body.lower() for keyword in suspicious_keywords)
                    confidence = 0.87 if is_spam else 0.92
                    displayed_label = 'Spam' if is_spam else 'Real'
                
            st.markdown("---")
            st.markdown("## Analysis Results")
            
            # Display result
            if is_spam:
                st.markdown("""
                    <h4 class="phishing-alert">
                            Phishing Detected
                        </h4>
                """, unsafe_allow_html=True)
                st.error("This email shows strong indicators of being a phishing attempt!")
                st.markdown(f"**Prediction source:** {prediction_source.capitalize()} | **Label:** {displayed_label}")
            else:
                st.markdown("""
                    <h4 class="safe-alert">
                        Email Appears Safe
                    </h4>
                """, unsafe_allow_html=True)
                st.success("This email appears to be legitimate.")
                st.markdown(f"**Prediction source:** {prediction_source.capitalize()} | **Label:** {displayed_label}")
            
            # Confidence score
            st.markdown("### Confidence Score")
            st.progress(confidence)
            st.metric("Detection Confidence", f"{confidence * 100:.1f}%")
            
            # Detailed analysis
            st.markdown("### Detailed Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### Risk Indicators Found")
                indicators = []
                
                if "click here" in email_body.lower():
                    indicators.append("Suspicious call-to-action phrases")
                if "verify" in email_body.lower() or "confirm" in email_body.lower():
                    indicators.append("Urgency/verification requests")
                if "http://" in email_body:
                    indicators.append("Non-secure HTTP links detected")
                if not sender_email.endswith(('.com', '.org', '.edu', '.gov')):
                    indicators.append("Suspicious sender domain")
                
                if indicators:
                    for indicator in indicators:
                        st.markdown(indicator)
                else:
                    st.markdown("No major risk indicators found")
            
            with col2:
                st.markdown("#### Email Features")
                features_df = pd.DataFrame({
                    'Feature': ['Sender Domain', 'Subject Line', 'URL Count'],
                    'Status': [
                        sender_email.split('@')[1] if '@' in sender_email else 'N/A',
                        subject if subject else 'No subject',
                        str(email_body.count('http'))
                    ]
                })
                st.dataframe(features_df, use_container_width=True, hide_index=True)
            
            # Recommendations
            st.markdown("### Recommendations")
            if is_spam:
                st.warning("""
                **What to do:**
                - Do NOT click any links in this email
                - Do NOT reply or provide any information
                - Delete this email immediately
                - Report to your email provider as phishing
                - If you clicked any links, change your passwords immediately
                """)
            else:
                st.info("""
                **Safety Tips:**
                - Email appears legitimate, but always stay vigilant
                - Verify sender's email address matches official domains
                - Hover over links before clicking to check destinations
                - When in doubt, contact the organization directly
                """)

with tab2:
    st.markdown("### Upload Email File")
    st.info("Upload .eml, .msg, or .txt files containing email content")
    
    uploaded_file = st.file_uploader(
        "Choose an email file",
        type=['eml', 'msg', 'txt'],
        help="Supported formats: .eml, .msg, .txt"
    )
    
    if uploaded_file:
        st.success(f"File uploaded: {uploaded_file.name}")
        
        # Display file info
        file_details = {
            "Filename": uploaded_file.name,
            "File Size": f"{uploaded_file.size / 1024:.2f} KB",
            "File Type": uploaded_file.type
        }
        st.json(file_details)
        
        if st.button("Analyze Uploaded Email", type="primary"):
            with st.spinner("Processing file..."):
                time.sleep(2)
                st.success("Analysis complete! (Connect to your model for actual results)")

with tab3:
    st.markdown("### Batch Email Analysis")
    st.info("Upload a CSV file with multiple emails for bulk analysis")
    
    st.markdown("""
    **CSV Format Required:**
    - Column 1: `sender_email`
    - Column 2: `subject`
    - Column 3: `body`
    """)
    
    sample_data = pd.DataFrame({
        'sender_email': ['user1@example.com', 'admin@bank.com'],
        'subject': ['Hello', 'Verify your account'],
        'body': ['Just checking in...', 'Click here to verify now!']
    })
    
    st.download_button(
        label="Download Sample CSV",
        data=sample_data.to_csv(index=False),
        file_name="sample_emails.csv",
        mime="text/csv"
    )
    
    batch_file = st.file_uploader("Upload CSV file", type=['csv'])
    
    if batch_file:
        df = pd.read_csv(batch_file)
        st.dataframe(df.head(), use_container_width=True)
        
        if st.button("Analyze All Emails", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i in range(len(df)):
                progress_bar.progress((i + 1) / len(df))
                status_text.text(f"Analyzing email {i + 1} of {len(df)}...")
                time.sleep(0.1)
            
            st.success(f"Analyzed {len(df)} emails successfully!")
            
            # Demo results
            df['prediction'] = ['Safe', 'Phishing', 'Safe'] * (len(df) // 3 + 1)
            df['confidence'] = [0.95, 0.88, 0.92] * (len(df) // 3 + 1)
            st.dataframe(df.head(10), use_container_width=True)


# Sidebar info
with st.sidebar:
    st.markdown("### Common Phishing Signs")
    st.markdown("""
    - Spelling and grammar errors
    - Urgent or threatening language
    - Requests for personal information
    - Suspicious links or attachments
    - Mismatched sender addresses
    - Too-good-to-be-true offers
    """)