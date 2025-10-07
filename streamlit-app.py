import streamlit as st
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from datetime import datetime, timezone
import json
import os
import zipfile
import io

# -----------------------------
# Streamlit Config
# -----------------------------
st.set_page_config(layout="wide")

# -----------------------------
# Simple Auth Helpers
# -----------------------------
def get_credentials():
    # Fallbacks let you test locally without secrets set (NOT recommended for prod)
    username = st.secrets.get("auth", {}).get("username", os.getenv("APP_USERNAME", ""))
    password = st.secrets.get("auth", {}).get("password", os.getenv("APP_PASSWORD", ""))
    # if None print warning
    if username is None or password is None:
        st.warning("Warning: Auth credentials not set in secrets or environment variables.")
    return username, password

def login_form():
    st.title("🔐 Secure Access")
    with st.form("login"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
    return submit, u, p

def require_auth():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        return True

    submit, u, p = login_form()
    valid_u, valid_p = get_credentials()

    # If secrets aren't set, show a friendly hint
    if valid_u == "" or valid_p == "":
        st.info(
            "No credentials configured. "
            "Set `[auth].username` and `[auth].password` in Streamlit Secrets."
        )

    if submit:
        if u == valid_u and p == valid_p and valid_u != "" and valid_p != "":
            st.session_state.authenticated = True
            st.success("✅ Access granted")
            st.rerun()
        else:
            st.error("❌ Invalid credentials")

    return False

def logout_button():
    with st.sidebar:
        if st.button("🚪 Logout"):
            st.session_state.authenticated = False
            st.experimental_rerun()

# -----------------------------
# S3 listing (with pagination)
# -----------------------------
def list_all_objects(s3_client, bucket_name, prefix=""):
    kwargs = {"Bucket": bucket_name}
    if prefix:
        kwargs["Prefix"] = prefix
    while True:
        resp = s3_client.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            yield obj
        if resp.get("IsTruncated"):
            kwargs["ContinuationToken"] = resp["NextContinuationToken"]
        else:
            break

# -----------------------------
# Tree building
# Directories => dict
# Files => None
# -----------------------------
def insert_path(tree: dict, key: str):
    parts = [p for p in key.split("/") if p != ""]
    if not parts:
        return
    cur = tree
    for i, part in enumerate(parts):
        last = (i == len(parts) - 1)
        if last:
            cur.setdefault(part, None)  # file
        else:
            cur = cur.setdefault(part, {})  # dir

def build_tree(s3_client, bucket_name):
    tree = {}
    any_found = False
    for obj in list_all_objects(s3_client, bucket_name):
        key = obj["Key"]
        if key.endswith("/"):
            continue
        any_found = True
        insert_path(tree, key)
    return tree if any_found else {}

# -----------------------------
# Mentor JSON loader (MINIFIED)
# -----------------------------
def collect_mentor_state_contents(s3_client, bucket_name):
    """
    Load mentors/<id>/mentor_state.json and return map of
    top-level key:value (nested dicts shown inline).
    """
    result = {}
    for obj in list_all_objects(s3_client, bucket_name, prefix="mentors/"):
        key = obj["Key"]
        if key.endswith("/"):
            continue
        parts = key.split("/")
        if len(parts) == 3 and parts[0] == "mentors" and parts[2] == "mentor_state.json":
            try:
                body = s3_client.get_object(Bucket=bucket_name, Key=key)["Body"].read()
                try:
                    text = body.decode("utf-8")
                except UnicodeDecodeError:
                    text = body.decode("latin-1")
                parsed = json.loads(text)

                lines = []
                for k, v in parsed.items():
                    if isinstance(v, dict):
                        val = json.dumps(v, separators=(", ", ": "), ensure_ascii=False)
                    elif isinstance(v, list):
                        if len(v) > 10:
                            val = "[" + ", ".join(map(str, v[:10])) + ", ...]"
                        else:
                            val = json.dumps(v, ensure_ascii=False)
                    else:
                        val = json.dumps(v, ensure_ascii=False)
                    lines.append(f"{k}: {val}")

                result[tuple(parts)] = lines or ["{}"]
            except Exception as e:
                result[tuple(parts)] = [f"_error: Failed to load ({e})"]
    return result

# -----------------------------
# Render tree with inline JSON
# -----------------------------
def build_tree_lines(tree, mentor_json_map, prefix="", path_prefix=()):
    # Directories first, then files
    dirs = sorted([k for k, v in tree.items() if isinstance(v, dict)])
    files = sorted([k for k, v in tree.items() if v is None])
    keys = dirs + files

    lines = []
    for i, name in enumerate(keys):
        is_last = (i == len(keys) - 1)
        connector = "└── " if is_last else "├── "
        is_dir = isinstance(tree[name], dict)
        lines.append(f"{prefix}{connector}{name}")

        # 6-space bump (wide indent)
        extension = "      " if is_last else "│     "

        if is_dir:
            lines.extend(
                build_tree_lines(tree[name], mentor_json_map, prefix + extension, path_prefix + (name,))
            )
        else:
            full_path = path_prefix + (name,)
            if len(full_path) == 3 and full_path[0] == "mentors" and full_path[2] == "mentor_state.json":
                json_lines = mentor_json_map.get(full_path, None)
                if json_lines:
                    for jl in json_lines:
                        lines.append(f"{prefix}{extension}{jl}")
    return lines

def display_tree_with_inline_json(tree, mentor_json_map):
    lines = build_tree_lines(tree, mentor_json_map)
    st.code("\n".join(lines), language="text")

def fetch_orchestration_report(s3_client, bucket_name, filename="orchestration_report.txt"):
    """Fetch the orchestration_report.txt file content from S3 root (if exists)."""
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=filename)
        content = response["Body"].read().decode("utf-8")
        return content
    except s3_client.exceptions.NoSuchKey:
        return None
    except Exception as e:
        st.warning(f"Failed to load {filename}: {str(e)}")
        return None

def preview_s3_storage():
    # with st.secrets - using lowercase 'aws' to match secrets.toml
    aws_access_key = st.secrets.get('aws', {}).get("AWS_ACCESS_KEY_ID", "")
    aws_secret_key = st.secrets.get('aws', {}).get("AWS_SECRET_ACCESS_KEY", "")
    aws_region = st.secrets.get('aws', {}).get("AWS_REGION", "")
    bucket_name = st.secrets.get('aws', {}).get("S3_BUCKET_NAME", "")

    # Debug information (remove in production)
    if not aws_access_key or not aws_secret_key or not aws_region or not bucket_name:
        st.error("❌ Missing AWS configuration:")
        st.write(f"- Access Key: {'✅' if aws_access_key else '❌'}")
        st.write(f"- Secret Key: {'✅' if aws_secret_key else '❌'}")
        st.write(f"- Region: {'✅' if aws_region else '❌'} ({aws_region})")
        st.write(f"- Bucket Name: {'✅' if bucket_name else '❌'} ({bucket_name})")
        return

    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region,
        )

        # Show timestamp
        st.write(f"Last updated: `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}`")

        # Build and display tree
        tree = build_tree(s3, bucket_name)
        if not tree:
            st.warning("Bucket is empty or not found.")
            return

        st.write(f"S3 bucket: `{bucket_name}`")

        mentor_json_map = collect_mentor_state_contents(s3, bucket_name)
        display_tree_with_inline_json(tree, mentor_json_map)

        report = fetch_orchestration_report(s3, bucket_name)
        if report:
            st.subheader("🧾 Orchestration Report")
            st.code(report, language="text")  # read-only, scrollable
        else:
            st.info("No orchestration_report.txt found at the root of the bucket.")

    except (NoCredentialsError, PartialCredentialsError):
        st.error("Invalid AWS credentials. Please check your keys.")
    except Exception as e:
        st.error(f"Error: {str(e)}")

# -----------------------------
# Browser download functionality
# -----------------------------
def create_s3_folder_zip(bucket_name, s3_folder="mentors/"):
    """
    Create a ZIP file in memory containing all files from the specified S3 folder.
    Returns the ZIP file as bytes for browser download.
    """
    try:
        # Get AWS credentials from secrets
        aws_access_key = st.secrets.get('aws', {}).get("AWS_ACCESS_KEY_ID", "")
        aws_secret_key = st.secrets.get('aws', {}).get("AWS_SECRET_ACCESS_KEY", "")
        aws_region = st.secrets.get('aws', {}).get("AWS_REGION", "")
        
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        )

        # Create a BytesIO object to store the ZIP file in memory
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            paginator = s3.get_paginator('list_objects_v2')
            file_count = 0

            for page in paginator.paginate(Bucket=bucket_name, Prefix=s3_folder):
                for obj in page.get('Contents', []):
                    key = obj['Key']
                    if key.endswith("/"):  # skip folder entries
                        continue

                    try:
                        # Download file content to memory
                        file_obj = s3.get_object(Bucket=bucket_name, Key=key)
                        file_content = file_obj['Body'].read()

                        # Add file to ZIP with relative path (remove s3_folder prefix)
                        relative_path = os.path.relpath(key, s3_folder) if s3_folder else key
                        zip_file.writestr(relative_path, file_content)
                        file_count += 1

                    except Exception as e:
                        st.warning(f"Failed to download {key}: {str(e)}")
                        continue

            # Add a summary file to the ZIP
            timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            summary = f"""S3 Folder Download Summary
============================
Bucket: {bucket_name}
Folder: {s3_folder}
Downloaded: {file_count} files
Timestamp: {timestamp}
"""
            zip_file.writestr("download_summary.txt", summary)

        zip_buffer.seek(0)
        return zip_buffer.getvalue(), file_count

    except Exception as e:
        st.error(f"Error creating ZIP file: {str(e)}")
        return None, 0

# -----------------------------
# Main App UI (gated)
# -----------------------------
def app_ui():
    st.title("🗂️ S3 Bucket Explorer")

    # Download whole bucket
    st.subheader("📥 Download Bucket")
    bucket_name = st.secrets.get('aws', {}).get("S3_BUCKET_NAME", "")

    s3_folder = ""  # empty prefix = entire bucket

    # Action buttons
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    with col2:
        if st.button("📦 Prepare Download", use_container_width=True):
            with st.spinner("Creating ZIP file from entire bucket..."):
                zip_data, file_count = create_s3_folder_zip(bucket_name, s3_folder)

                if zip_data:
                    st.session_state.zip_data = zip_data
                    st.session_state.file_count = file_count
                    st.success(f"✅ ZIP file ready! Contains {file_count} files from the whole bucket.")
                else:
                    st.error("❌ Failed to create ZIP file.")

    with col3:
        if hasattr(st.session_state, 'zip_data') and st.session_state.zip_data:
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            filename = f"entire_bucket_{timestamp}.zip"
            st.download_button(
                label="💾 Download ZIP",
                data=st.session_state.zip_data,
                file_name=filename,
                mime="application/zip",
                use_container_width=True,
                help=f"Downloads {st.session_state.file_count} files"
            )
        else:
            st.button("💾 Download ZIP", disabled=True, use_container_width=True,
                      help="Click 'Prepare Download' first")

    # Show status
    if hasattr(st.session_state, 'file_count'):
        st.info(f"📄 Ready to download: **{st.session_state.file_count} files** from **entire bucket**")

    st.divider()

    # Display the S3 structure
    st.subheader("🗂️ Bucket Contents")
    preview_s3_storage()

def main():
    # Gate everything behind auth
    if require_auth():
        logout_button()  # shows in sidebar
        app_ui()

if __name__ == "__main__":
    main()