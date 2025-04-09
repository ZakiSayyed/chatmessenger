# streamlit_chat_app.py
import streamlit as st
import pandas as pd
import hashlib
import base64
from datetime import datetime
from google.oauth2 import service_account
from gspread_pandas import Spread, Client
import time

# --- Setup Google Sheets connection ---
# Update the scope variable with valid Google API scopes
scope = ['https://www.googleapis.com/auth/spreadsheets',
         'https://www.googleapis.com/auth/drive']
creds_dict = st.secrets["gcp_service_account"]
credentials = service_account.Credentials.from_service_account_info(dict(creds_dict), scopes=scope)
spread = Spread('1Bsv2n_12_wmWhNI5I5HgCmBWsVyAHFw3rfTGoIrT5ho', creds=credentials)
client = spread.client
sh = client.open_by_key('1Bsv2n_12_wmWhNI5I5HgCmBWsVyAHFw3rfTGoIrT5ho')

# --- Helper Functions ---
# def hash_password(password):
#     return hashlib.sha256(password.encode()).hexdigest()

def get_users():
    df = spread.sheet_to_df(sheet='users', index=False)
    if df.empty or 'email' not in df.columns:
        st.warning("The 'users' sheet is empty or missing required columns.")
        return pd.DataFrame(columns=['email', 'username', 'password', 'status'])
    return df

def get_friends(user):
    df = spread.sheet_to_df(sheet='friends', index=False)
    # st.write("Raw Friends DataFrame:", df)  # Debug: Display the raw DataFrame
    # st.write("Raw Columns:", df.columns.tolist())  # Debug: Display the raw column names
    df.columns = df.columns.str.strip().str.lower()  # Normalize column names
    # st.write("Normalized Columns:", df.columns.tolist())  # Debug: Display normalized column names
    if 'user_email' not in df.columns or 'friend_email' not in df.columns:
        st.error("The 'friends' sheet is missing required columns.")
        return []
    return df[df['user_email'] == user]['friend_email'].tolist()

def get_friend_requests(user):
    df = spread.sheet_to_df(sheet='friend_requests', index=False)
    df.columns = df.columns.str.strip().str.lower()  # Normalize column names
    # Explicitly rename columns if necessary
    df.rename(columns={
        'sender_email': 'sender_email',
        'receiver_email': 'receiver_email',
        'status': 'status'
    }, inplace=True)
    # st.write("Friend Requests DataFrame:", df)  # Debug: Display the DataFrame
    # st.write("Columns:", df.columns.tolist())  # Debug: Display the column names
    if 'sender_email' not in df.columns or 'receiver_email' not in df.columns or 'status' not in df.columns:
        st.error("The 'friend_requests' sheet is missing required columns.")
        return pd.DataFrame(columns=['sender_email', 'receiver_email', 'status'])
    return df[(df['receiver_email'] == user) & (df['status'] == 'Pending')]

def get_messages(user, friend):
    df = spread.sheet_to_df(sheet='messages', index=False)
    # st.write("Raw Messages DataFrame:", df)  # Debug: Display the raw DataFrame
    # st.write("Raw Columns:", df.columns.tolist())  # Debug: Display the raw column names
    df.columns = df.columns.str.strip().str.lower()  # Normalize column names

    # Handle misspelled columns
    df.rename(columns={
        'reciever_email': 'receiver_email'  # Correct the misspelled column
    }, inplace=True)

    # st.write("Normalized Columns:", df.columns.tolist())  # Debug: Display normalized column names
    if 'sender_email' not in df.columns or 'receiver_email' not in df.columns:
        st.error("The 'messages' sheet is missing required columns.")
        return pd.DataFrame(columns=['sender_email', 'receiver_email', 'message', 'timestamp', 'type', 'image_data'])
    mask = ((df['sender_email'] == user) & (df['receiver_email'] == friend)) | \
           ((df['sender_email'] == friend) & (df['receiver_email'] == user))
    return df[mask].sort_values(by='timestamp')

def update_status(user, status):
    df = get_users()
    df.loc[df['email'] == user, 'status'] = status
    spread.df_to_sheet(df, sheet='users', index=False)  # Overwrite the entire 'users' sheet

# --- Signup ---
def signup(email, username, password):
    users_df = get_users()
    if email in users_df['email'].values:
        st.warning("Email already registered.")
        return
    new_user = [email, username, password, 'Offline']
    # Append the new user to the sheet
    worksheet = sh.worksheet('users')  # Access the 'users' sheet
    worksheet.append_row(new_user, value_input_option='RAW')  # Append the new row
    st.success("Signup successful! Please login.")

# --- Login ---
def login(email, password):
    users_df = get_users()
    user = users_df[users_df['email'] == email]
    if user.empty or password != user.iloc[0]['password']:
        st.error("Invalid credentials.")
        return False
    st.session_state.user = email
    return True

# --- Send Friend Request ---
def send_friend_request(sender, receiver_email):
    users_df = get_users()
    if receiver_email not in users_df['email'].values:
        st.warning("User does not exist.")
        return
    new_request = [sender, receiver_email, 'Pending']
    worksheet = sh.worksheet('friend_requests')  # Access the 'friend_requests' sheet
    worksheet.append_row(new_request, value_input_option='RAW')  # Append the new row
    st.success("Friend request sent.")

# --- Accept Friend Request ---
def accept_friend_request(sender, receiver):
    df = spread.sheet_to_df(sheet='friend_requests', index=False)
    # st.write("Raw Friend Requests DataFrame:", df)  # Debug: Display the raw DataFrame
    # st.write("Raw Columns:", df.columns.tolist())  # Debug: Display the raw column names
    df.columns = df.columns.str.strip().str.lower()  # Normalize column names
    # st.write("Normalized Columns:", df.columns.tolist())  # Debug: Display normalized column names
    if 'sender_email' not in df.columns or 'receiver_email' not in df.columns or 'status' not in df.columns:
        st.error("The 'friend_requests' sheet is missing required columns.")
        return
    df.loc[(df['sender_email'] == sender) & (df['receiver_email'] == receiver), 'status'] = 'Accepted'
    spread.df_to_sheet(df, sheet='friend_requests', index=False)  # Overwrite the entire sheet

    # Append the new friendship to the 'friends' sheet
    friends_df = pd.DataFrame([[receiver, sender], [sender, receiver]],
                              columns=['user_email', 'friend_email'])
    worksheet = sh.worksheet('friends')  # Access the 'friends' sheet
    for _, row in friends_df.iterrows():
        worksheet.append_row(row.tolist(), value_input_option='RAW')  # Append each row
    st.success(f"You are now friends with {sender}.")


# --- Send Message ---
def send_message(sender, receiver, message, msg_type='text', image_data=None):
    now = datetime.utcnow().isoformat()
    new_msg = [sender, receiver, message, now, msg_type, image_data]
    worksheet = sh.worksheet('messages')  # Access the 'messages' sheet
    worksheet.append_row(new_msg, value_input_option='RAW')  # Append the new message

# --- Main App ---
def main():
    st.title("📨 Messenger Online")

    if 'user' not in st.session_state:
        menu = st.sidebar.selectbox("Menu", ["Login", "Signup"])

        if menu == "Signup":
            email = st.text_input("Email")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Signup"):
                signup(email, username, password)

        if menu == "Login":
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if login(email, password):
                    st.rerun()
    else:
        st.sidebar.subheader(f"Logged in as: {st.session_state.user}")
        action = st.sidebar.radio("Select", ["Dashboard", "Chat", "Logout"])

        if action == "Dashboard":
            status = st.selectbox("Set your status", ["Online", "Away", "Offline"])
            update_status(st.session_state.user, status)
            
            # st.success("Status updated.")
            msg = st.empty()
            msg.success("Status updated.")
            time.sleep(1)
            msg.empty()
            with st.expander("Send Friend Request"):
                target_email = st.text_input("Friend's Email")
                if st.button("Send Request"):
                    send_friend_request(st.session_state.user, target_email)

            with st.expander("Friend Requests"):
                requests = get_friend_requests(st.session_state.user)
                for _, row in requests.iterrows():
                    col1, col2 = st.columns(2)
                    col1.write(f"From: {row['sender_email']}")
                    if col2.button("Accept", key=row['sender_email']):
                        accept_friend_request(row['sender_email'], st.session_state.user)

        # --- Chat Section ---
        # --- Chat Section ---
        elif action == "Chat":
            friends = get_friends(st.session_state.user)
            if not friends:
                st.info("No friends to chat with.")
                return

            friend = st.selectbox("Choose a friend", friends)

            # Fetch messages
            msgs = get_messages(st.session_state.user, friend)

            # Display chat history in a scrollable container
            st.markdown("### Chat History")
            chat_container = st.container()

            with chat_container:
                # Limit to the 10 most recent messages
                recent_msgs = msgs.tail(10)

                # Display the 10 most recent messages
                for _, msg in recent_msgs.iterrows():
                    sender = "You" if msg['sender_email'] == st.session_state.user else friend
                    timestamp = msg['timestamp'][11:16]
                    if msg['type'] == 'text':
                        st.write(f"**{sender} ({timestamp})**: {msg['message']}")
                    else:
                        st.write(f"**{sender} ({timestamp})**:")
                        st.image(base64.b64decode(msg['image_data']), use_column_width=True)

                # Add a scrollable container for older messages
                with st.expander("View Older Messages"):
                    older_msgs = msgs.iloc[:-10]  # All messages except the last 10
                    for _, msg in older_msgs.iterrows():
                        sender = "You" if msg['sender_email'] == st.session_state.user else friend
                        timestamp = msg['timestamp'][11:16]
                        if msg['type'] == 'text':
                            st.write(f"**{sender} ({timestamp})**: {msg['message']}")
                        else:
                            st.write(f"**{sender} ({timestamp})**:")
                            st.image(base64.b64decode(msg['image_data']), use_column_width=True)

            # Input for sending messages
            msg_text = st.text_input("Type your message")
            if st.button("Send"):
                if msg_text.strip():  # Ensure the message is not empty or just whitespace
                    with st.spinner("Sending..."):
                        send_message(st.session_state.user, friend, msg_text)
                    st.experimental_rerun()  # Refresh the chat after sending a message
                else:
                    st.warning("Message cannot be empty.")


            # # Input for sending images
            # image_file = st.file_uploader("Send Image", type=['png', 'jpg', 'jpeg'])
            # if image_file:
            #     image_bytes = image_file.read()
            #     image_b64 = base64.b64encode(image_bytes).decode()
            #     if st.button("Send Image"):
            #         send_message(st.session_state.user, friend, 'Image', 'image', image_b64)
            #         st.rerun()  # Refresh the chat after sending an image

        elif action == "Logout":
            st.session_state.clear()
            st.rerun()

if __name__ == '__main__':
    main()
