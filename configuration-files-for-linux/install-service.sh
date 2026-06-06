#!/bin/bash

# -------------------------------------------------------------------
# Programmer       : Ebrahim Shafiei (EbraSha)
# Email            : Prof.Shafiei@Gmail.com
# chmod +x install-abdal-4iproto-server.sh && sudo install-abdal-4iproto-server.sh
# -------------------------------------------------------------------

SERVICE_NAME="abdal-4iproto-server.service"
SOURCE_PATH="$(dirname "$(realpath "$0")")/${SERVICE_NAME}"
TARGET_PATH="/etc/systemd/system/${SERVICE_NAME}"

if [ ! -f "${SOURCE_PATH}" ]; then
    echo "Service file not found: ${SOURCE_PATH}"
    exit 1
fi

cp "${SOURCE_PATH}" "${TARGET_PATH}"
chmod 644 "${TARGET_PATH}"

systemctl daemon-reload
systemctl enable abdal-4iproto-server.service
systemctl start abdal-4iproto-server.service

systemctl status abdal-4iproto-server.service --no-pager
