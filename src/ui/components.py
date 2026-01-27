# UI Reusable Components
import streamlit as st

def render_login_card():
    """Renders a nice card for the login status."""
    if st.session_state.user:
        st.success(f"Authenticated: {st.session_state.user.get('email', 'Guest')}")
    else:
        st.warning("Status: Unauthenticated (Guest Mode)")

def render_status_badge(status):
    """Renders a visual badge for vulnerability status."""
    if status == "CRITICAL":
        st.error("CRITICAL RISK DETECTED")
    elif status == "HIGH":
        st.warning("HIGH RISK DETECTED")
    elif status == "SAFE":
        st.success("SYSTEM SECURE")
    else:
        st.info("Analysis Inconclusive")