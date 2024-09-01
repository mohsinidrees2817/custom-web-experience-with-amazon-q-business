from datetime import datetime, timedelta, timezone
import jwt
import jwt.algorithms
import streamlit as st  # all streamlit commands will be available through the "st" alias
import utils
from streamlit_feedback import streamlit_feedback
import boto3
import webbrowser
UTC = timezone.utc

# Init configuration
utils.retrieve_config_from_agent()
if "aws_credentials" not in st.session_state:
    st.session_state.aws_credentials = None

st.set_page_config(page_title="Amazon Q Business Custom UI")  # HTML title
st.title("Amazon Q Business Custom UI")  # page title

# Define a function to clear the chat history
def clear_chat_history():
    st.session_state.messages = [{"role": "assistant", "content": "How may I assist you today?"}]
    st.session_state.questions = []
    st.session_state.answers = []
    st.session_state.input = ""
    st.session_state["chat_history"] = []
    st.session_state["conversationId"] = ""
    st.session_state["parentMessageId"] = ""

oauth2 = utils.configure_oauth_component()

# Check if 'token' is not in session state
if "token" not in st.session_state:
    # Redirect directly if no token is present
    redirect_uri = f"https://{utils.OAUTH_CONFIG['ExternalDns']}/component/streamlit_oauth.authorize_button/index.html"
    # st.query_params(redirect=redirect_uri)
    webbrowser.open_new_tab(redirect_uri)
    st.rerun()
else:
    token = st.session_state["token"]
    refresh_token = token["refresh_token"]  # saving the long-lived refresh_token
    user_email = jwt.decode(token["id_token"], options={"verify_signature": False})["email"]

    if "idc_jwt_token" not in st.session_state:
        st.session_state["idc_jwt_token"] = utils.get_iam_oidc_token(token["id_token"])
        st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + \
            timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
    elif st.session_state["idc_jwt_token"]["expires_at"] < datetime.now(UTC):
        # If the Identity Center token is expired, refresh the Identity Center token
        try:
            st.session_state["idc_jwt_token"] = utils.refresh_iam_oidc_token(
                st.session_state["idc_jwt_token"]["refreshToken"]
            )
            st.session_state["idc_jwt_token"]["expires_at"] = datetime.now(UTC) + \
                timedelta(seconds=st.session_state["idc_jwt_token"]["expiresIn"])
        except Exception as e:
            st.error(f"Error refreshing Identity Center token: {e}. Please reload the page.")

    user_name = jwt.decode(token["id_token"], options={"verify_signature": False})["cognito:username"]
    st.sidebar.text("Welcome: " + user_name)
    st.markdown(
        f"""
         <style>
            [data-testid="stSidebarNav"]::before {{
                content: "User: {user_email}";
                margin-left: 20px;
                margin-top: 20px;
                font-size: 30px;
                position: relative;
                top: 100px;
            }}
        """,
        unsafe_allow_html=True
    )

    if st.sidebar.button("logout"):
        utils.logout()
    st.button("Clear Chat History", on_click=clear_chat_history)

    # Initialize the chat messages in the session state if it doesn't exist
    if "messages" not in st.session_state:
        st.session_state["messages"] = []

    if "conversationId" not in st.session_state:
        st.session_state["conversationId"] = ""

    if "parentMessageId" not in st.session_state:
        st.session_state["parentMessageId"] = ""

    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []

    if "questions" not in st.session_state:
        st.session_state.questions = []

    if "answers" not in st.session_state:
        st.session_state.answers = []

    if "input" not in st.session_state:
        st.session_state.input = ""

    # Display the chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])

    # User-provided prompt
    if prompt := st.chat_input():
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.write(prompt)

    # Check if the last message is not from the assistant and messages list is not empty
    if st.session_state.messages and st.session_state.messages[-1]["role"] != "assistant":
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                placeholder = st.empty()
                response = utils.get_queue_chain(prompt, st.session_state["conversationId"],
                                                st.session_state["parentMessageId"],
                                                st.session_state["idc_jwt_token"]["idToken"])
                if "references" in response:
                    full_response = f"""{response["answer"]}\n\n---\n{response["references"]}"""
                else:
                    full_response = f"""{response["answer"]}\n\n---\nNo sources"""
                placeholder.markdown(full_response)
                st.session_state["conversationId"] = response["conversationId"]
                st.session_state["parentMessageId"] = response["parentMessageId"]

        st.session_state.messages.append({"role": "assistant", "content": full_response})
