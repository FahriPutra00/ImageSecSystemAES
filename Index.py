import streamlit as st
import streamlit_authenticator as stauth

hashed_passwords = stauth.Hasher([""]).generate()