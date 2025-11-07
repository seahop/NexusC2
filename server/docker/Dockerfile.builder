FROM golang:1.25-alpine

# Set up working directory
WORKDIR /app

# Install required tools and Garble for obfuscation
RUN apk add --no-cache git zip && \
    go install mvdan.cc/garble@v0.15.0

# Dynamically preload Go dependencies
RUN mkdir -p /preload && cd /preload && \
    MODULE_NAME=github.com/preloaded/dependencies && \
    go mod init $MODULE_NAME && \
    echo 'package main' > dummy.go && \
    echo 'import (' >> dummy.go && \
    echo '    _ "github.com/RIscRIpt/pecoff"' >> dummy.go && \
    echo '    _ "github.com/almounah/go-buena-clr"' >> dummy.go && \
    echo '    _ "github.com/creack/pty"' >> dummy.go && \
    echo '    _ "github.com/go-ole/go-ole"' >> dummy.go && \
    echo '    _ "golang.org/x/crypto/ssh"' >> dummy.go && \
    echo '    _ "golang.org/x/net/proxy"' >> dummy.go && \
    echo '    _ "github.com/gorilla/websocket"' >> dummy.go && \
    echo '    _ "github.com/shirou/gopsutil/v3/process"' >> dummy.go && \
    echo '    _ "github.com/go-ldap/ldap/v3"' >> dummy.go && \
    echo '    _ "golang.org/x/sys/windows"' >> dummy.go && \
    echo '    _ "golang.org/x/sys/unix"' >> dummy.go && \
    echo '    _ "github.com/stretchr/testify"' >> dummy.go && \
    echo '    _ "github.com/alexbrainman/sspi"' >> dummy.go && \
    echo '    _ "github.com/jcmturner/gokrb5/v8"' >> dummy.go && \
    echo '    _ "github.com/google/go-cmp/cmp"' >> dummy.go && \
    echo '    _ "golang.org/x/term"' >> dummy.go && \
    echo '    _ "github.com/davecgh/go-spew/spew"' >> dummy.go && \
    echo '    _ "github.com/pmezard/go-difflib/difflib"' >> dummy.go && \
    echo '    _ "gopkg.in/yaml.v3"' >> dummy.go && \
    echo '    _ "github.com/jcmturner/gofork"' >> dummy.go && \
    echo '    _ "github.com/jcmturner/goidentity/v6"' >> dummy.go && \
    echo '    _ "github.com/jcmturner/dnsutils/v2"' >> dummy.go && \
    echo '    _ "github.com/hashicorp/go-uuid"' >> dummy.go && \
    echo '    _ "github.com/jcmturner/rpc/v2/mstypes"' >> dummy.go && \
    echo '    _ "github.com/jcmturner/aescts/v2"' >> dummy.go && \
    echo '    _ "github.com/shoenig/test"' >> dummy.go && \
    echo '    _ "google.golang.org/grpc")' >> dummy.go && \
    echo ')' >> dummy.go && \
    echo 'func main() {}' >> dummy.go && \
    go mod edit \
        -require=github.com/RIscRIpt/pecoff@v0.0.0-20200923152459-a332238caa87 \
        -require=github.com/almounah/go-buena-clr@v0.1.0 \
        -require=github.com/creack/pty@v1.1.24 \
        -require=github.com/go-ole/go-ole@v1.3.0 \
        -require=golang.org/x/crypto@v0.29.0 \
        -require=golang.org/x/net@v0.31.0 \
        -require=github.com/gorilla/websocket@v1.5.1 \
        -require=github.com/shirou/gopsutil/v3@v3.24.1 \
        -require=github.com/go-ldap/ldap/v3@v3.4.6 \
        -require=golang.org/x/sys@v0.27.0 \
        -require=github.com/stretchr/testify@v1.8.4 \
        -require=github.com/alexbrainman/sspi@v0.0.0-20231016080023-1a75b4708caa \
        -require=github.com/jcmturner/gokrb5/v8@v8.4.4 \
        -require=github.com/google/go-cmp@v0.6.0 \
        -require=golang.org/x/term@v0.15.0 \
        -require=github.com/davecgh/go-spew@v1.1.1 \
        -require=github.com/pmezard/go-difflib@v1.0.0 \
        -require=gopkg.in/yaml.v3@v3.0.1 \
        -require=github.com/jcmturner/gofork@v1.7.6 \
        -require=github.com/jcmturner/goidentity/v6@v6.0.1 \
        -require=github.com/jcmturner/dnsutils/v2@v2.0.0 \
        -require=github.com/hashicorp/go-uuid@v1.0.3 \
        -require=github.com/jcmturner/rpc/v2@v2.0.3 \
        -require=github.com/jcmturner/aescts/v2@v2.0.0 \
        -require=github.com/shoenig/test@v1.7.0 && \
    go mod tidy

# Ensure the dynamically created go.mod and go.sum are used during runtime
ENV GO_MOD_PATH=/preload

# Build-time arguments
ARG BUILD
ARG XOR_KEY
ARG OS
ARG ARCH
ARG OUTPUT_FILENAME
ARG CLIENTID
ARG GET_ROUTE
ARG POST_ROUTE
ARG GET_METHOD
ARG POST_METHOD
ARG GET_CLIENT_ID_NAME
ARG GET_CLIENT_ID_FORMAT
ARG POST_CLIENT_ID_NAME
ARG POST_CLIENT_ID_FORMAT
ARG POST_SECRET_NAME
ARG POST_SECRET_FORMAT
ARG USER_AGENT
ARG CONTENT_TYPE
ARG CUSTOM_HEADERS
ARG SLEEP
ARG JITTER
ARG PUBLIC_KEY
ARG SECRET
ARG PROTOCOL
ARG IP
ARG PORT

# Safety check arguments
ARG SAFETY_HOSTNAME
ARG SAFETY_USERNAME
ARG SAFETY_DOMAIN
ARG SAFETY_FILE_PATH
ARG SAFETY_FILE_MUST_EXIST
ARG SAFETY_PROCESS
ARG SAFETY_KILL_DATE
ARG SAFETY_WORK_HOURS_START
ARG SAFETY_WORK_HOURS_END

# Set environment variables
ENV BUILD=${BUILD}
ENV XOR_KEY=${XOR_KEY}
ENV OS=${OS}
ENV ARCH=${ARCH}
ENV OUTPUT_FILENAME=${OUTPUT_FILENAME}
ENV CLIENTID=${CLIENTID}
ENV GET_ROUTE=${GET_ROUTE}
ENV POST_ROUTE=${POST_ROUTE}
ENV GET_METHOD=${GET_METHOD}
ENV POST_METHOD=${POST_METHOD}
ENV GET_CLIENT_ID_NAME=${GET_CLIENT_ID_NAME}
ENV GET_CLIENT_ID_FORMAT=${GET_CLIENT_ID_FORMAT}
ENV POST_CLIENT_ID_NAME=${POST_CLIENT_ID_NAME}
ENV POST_CLIENT_ID_FORMAT=${POST_CLIENT_ID_FORMAT}
ENV POST_SECRET_NAME=${POST_SECRET_NAME}
ENV POST_SECRET_FORMAT=${POST_SECRET_FORMAT}
ENV USER_AGENT=${USER_AGENT}
ENV CONTENT_TYPE=${CONTENT_TYPE}
ENV CUSTOM_HEADERS=${CUSTOM_HEADERS}
ENV SLEEP=${SLEEP}
ENV JITTER=${JITTER}
ENV PUBLIC_KEY=${PUBLIC_KEY}
ENV SECRET=${SECRET}
ENV PROTOCOL=${PROTOCOL}
ENV IP=${IP}
ENV PORT=${PORT}

# Safety check environment variables
ENV SAFETY_HOSTNAME=${SAFETY_HOSTNAME}
ENV SAFETY_USERNAME=${SAFETY_USERNAME}
ENV SAFETY_DOMAIN=${SAFETY_DOMAIN}
ENV SAFETY_FILE_PATH=${SAFETY_FILE_PATH}
ENV SAFETY_FILE_MUST_EXIST=${SAFETY_FILE_MUST_EXIST}
ENV SAFETY_PROCESS=${SAFETY_PROCESS}
ENV SAFETY_KILL_DATE=${SAFETY_KILL_DATE}
ENV SAFETY_WORK_HOURS_START=${SAFETY_WORK_HOURS_START}
ENV SAFETY_WORK_HOURS_END=${SAFETY_WORK_HOURS_END}

# Toggle-specific environment variables
ENV TOGGLE_CHECK_ENVIRONMENT=${TOGGLE_CHECK_ENVIRONMENT}
ENV TOGGLE_CHECK_TIME_DISCREPANCY=${TOGGLE_CHECK_TIME_DISCREPANCY}
ENV TOGGLE_CHECK_MEMORY_PATTERNS=${TOGGLE_CHECK_MEMORY_PATTERNS}
ENV TOGGLE_CHECK_PARENT_PROCESS=${TOGGLE_CHECK_PARENT_PROCESS}
ENV TOGGLE_CHECK_LOADED_LIBRARIES=${TOGGLE_CHECK_LOADED_LIBRARIES}
ENV TOGGLE_CHECK_DOCKER_CONTAINER=${TOGGLE_CHECK_DOCKER_CONTAINER}
ENV TOGGLE_CHECK_PROCESS_LIST=${TOGGLE_CHECK_PROCESS_LIST}
# Copy entrypoint script
COPY payloads/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]