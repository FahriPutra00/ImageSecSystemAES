import streamlit as st
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
from streamlit_option_menu import option_menu
import warnings
import hashlib


warnings.filterwarnings("ignore")
st.config.set_option("deprecation.showPyplotGlobalUse", False)
st.set_page_config(
    page_title="Crypto Image",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://www.extremelycoolapp.com/help',
        'Report a bug': "https://www.extremelycoolapp.com/bug",
        'About': "Crypto Image With BASE64 Encryption"
    }
)

# Fungsi untuk mengenkripsi teks menggunakan AES
def encrypt_text(text, key):
    # Generate a 16-byte (128-bit) key using SHA-256
    key = hashlib.sha256(key).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text, AES.block_size))
    return encrypted_text

# Fungsi untuk mendekripsi teks yang telah dienkripsi menggunakan AES
def decrypt_text(encrypted_text, key):
    # Generate a 16-byte (128-bit) key using SHA-256
    key = hashlib.sha256(key).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
    return decrypted_text


# Function to encrypt image using BASE64 and AES
def encrypt_image(file_data, key):
    encrypted_data = encrypt_text(file_data, key)
    encoded_data = base64.b64encode(encrypted_data).decode('ascii')
    return encoded_data

# Function to decrypt image that has been encrypted using BASE64 and AES
def decrypt_image(encoded_data, key):
    decoded_data = base64.b64decode(encoded_data.encode('ascii'))
    decrypted_data = decrypt_text(decoded_data, key)
    return decrypted_data

def save_text_to_file(text, file_name):
    with open(file_name, "w") as file:
        file.write(text)

# Streamlit app
def main():
    with st.sidebar:
        selected = option_menu("Menu",["Encoding Image","Decoding Image","About"],
                            icons=['file-earmark-arrow-up','blockquote-left', 'gear'], menu_icon="cast",
                            default_index=0, styles={
            "container": {"padding": "5!important", "padding-top":"0px"},
            "nav-link": {"font-size": "16px", "text-align": "left", "margin":"5px"},
        })
    st.title("Image Encoder/Decoder With BASE64 Encryption and AES")
    st.write("This application encrypts and decrypts images using BASE64 and AES encryption.")
    if selected =='Encoding Image':   
        st.title("Encrypt Image using BASE64 and AES")
        file = st.file_uploader("Select an image file to encrypt", type=["jpg", "png", "jpeg"], key="file_uploader", 
                                help="Only .jpg, .png, .jpeg files allowed", accept_multiple_files=False)
        if file is not None:
            file_data = file.read()
            with st.container():
                col1, col2 = st.columns(2)
                with col1:
                    st.image(file_data, use_column_width=True)
                with col2:
                    st.header("Select Output Encryption Format")
                    st.write("""Encryption using BASE64 and AES. BASE64 transformation is an algorithm for encoding and decoding
                    data into ASCII format, which is based on a base-64 number system. The resulting characters in this Base64 transformation
                    consist of A..Z, a..z, and 0..9, as well as two additional symbolic characters, namely + and /, and one equal sign (=)
                    character used for padding and aligning binary data.""")
                    key = st.text_input("Enter encryption key:")
                    download_format = st.radio("Select output format", ("PNG", "JPG", "JPEG", "TXT"))
                    if st.button("Encrypt"):
                        key = key.encode('utf-8')  # Convert key to bytes
                        encoded_data = encrypt_image(file_data, key)
                        st.success("File encrypted successfully!")
                        st.text_area("Encoded Text", value=encoded_data)
                        
                        if download_format:
                            file_extension = download_format.lower()
                            file_name = f"encrypted_image.{file_extension}"
                            if file_extension == "png":
                                mime_type = "image/png"
                                encoded_data_bytes = encoded_data.encode('ascii')
                                st.download_button(rf"Download Encoded Image (.{download_format})", data=encoded_data_bytes,
                                                file_name=file_name, mime=mime_type)
                            elif file_extension == "jpg":
                                mime_type = "image/jpeg"
                                encoded_data_bytes = encoded_data.encode('ascii')
                                st.download_button(rf"Download Encoded Image (.{download_format})", data=encoded_data_bytes,
                                                file_name=file_name, mime=mime_type)
                            elif file_extension == "jpeg":
                                mime_type = "image/jpeg"
                                encoded_data_bytes = encoded_data.encode('ascii')
                                st.download_button(rf"Download Encoded Image (.{download_format})", data=encoded_data_bytes,
                                                file_name=file_name, mime=mime_type)
                            elif file_extension == "txt":
                                save_text_to_file(encoded_data, "EncodedImage.txt")
                                st.download_button(rf"Download Encoded Image (.{download_format})", data=open("EncodedImage.txt", 'rb').read(), file_name="EncodedImage.txt")
                            else:
                                mime_type = None

    if selected =='Decoding Image':
        st.title("Decrypt Image using BASE64 and AES")
        file = st.file_uploader("Select an encoded file", type=["txt","png", "jpg", "jpeg"], key="file_uploader", 
                                help="Only .txt, .png, .jpg, .jpeg files allowed", accept_multiple_files=False)
        encoded_text = st.text_area("Enter the encoded text")
        col1, col2 = st.columns(2)
        with col1:
            key = st.text_input("Enter decryption key:")
        with col2:
            download_format = st.radio("Select output format", ("PNG", "JPG", "JPEG"))
        if file is not None or encoded_text:
            if file is not None:
                encoded_text = file.read().decode('utf-8')
            if st.button("Decrypt"):
                key = key.encode('utf-8')  # Convert key to bytes
                decrypted_image = decrypt_image(encoded_text, key)
                st.success("Text decrypted successfully!")
                with st.container():
                    col1, col2 = st.columns(2)
                    with col1:
                        st.image(decrypted_image, use_column_width=True)
                    with col2:
                        if download_format:
                            file_extension = download_format.lower()
                            file_name_dec = f"encrypted_image.{file_extension}"
                            if file_extension == "png":
                                mime_type = "image/png"
                            elif file_extension == "jpg":
                                mime_type = "image/jpeg"
                            elif file_extension == "jpeg":
                                mime_type = "image/jpeg"
                        st.download_button(rf"Download Decoded {download_format}", data=decrypted_image, file_name=file_name_dec, mime=mime_type)


if __name__ == "__main__":
    main()
