#!/bin/bash -e

CN='ssl'
SSL_IP=''
SSL_DNS=''

C=CN

SSL_SIZE=2048

DATE=${DATE:-3650}

SSL_CONFIG='openssl.cnf'

help() {
    cat <<-EOF

Usage: ./certgen.sh [OPTIONS] COMMAND

A script for zkm cert generation.

Options:
--help Get the help info and exit
--cn Common name of the server
--ssl-ip Extended trust ips, such as 127.0.0.1, 0.0.0.0
--ssl-dns Extended trust dns, such as demo.zkm.com
--ssl-size The key size
--date Validity of the certificate
--ssl-config Address of config file
EOF
    exit 0
}

echo 'cn', $2

while [ -n "$1" ]; do
    case "$1" in
    --cn)
        CN="$2"
        shift
        ;;
    --ssl-ip)
        SSL_IP="$2"
        shift
        ;;
    --ssl-dns)
        SSL_DNS="$2"
        shift
        ;;
    --ssl-size)
        SSL_SIZE=$2
        shift
        ;;
    --date)
        DATE=$2
        shift
        ;;
    --ssl-config)
        SSL_CONFIG="$2"
        shift
        ;;
    -h | --help)
        help
        ;;
    --)
        shift
        break
        ;;
    *)
        echo "Error: not defined option."
        exit 1
        ;;
    esac
    shift
done

echo "----------------------------"
echo "| SSL Cert Generator |"
echo "----------------------------"
echo

export CA_KEY=${CA_KEY-"ca.key"}
export CA_CERT=${CA_CERT-"ca.pem"}
export CA_SUBJECT=ca-$CN
export CA_EXPIRE=${DATE}

export SSL_CONFIG=${SSL_CONFIG}
export SSL_KEY=$CN.key
export SSL_CSR=$CN.csr
export SSL_CERT=$CN.pem
export SSL_EXPIRE=${DATE}

export SSL_SUBJECT=${CN}
export SSL_DNS=${SSL_DNS}
export SSL_IP=${SSL_IP}

echo ${CA_SUBJECT}
echo ${CN}
echo "--> Certificate Authority"

if [[ -e ./${CA_KEY} ]]; then
    echo "====> Using existing CA Key ${CA_KEY}"
else
    echo "====> Generating new CA key ${CA_KEY}"
    openssl genrsa -out ${CA_KEY} ${SSL_SIZE} >/dev/null
fi

if [[ -e ./${CA_CERT} ]]; then
    echo "====> Using existing CA Certificate ${CA_CERT}"
else
    echo "====> Generating new CA Certificate ${CA_CERT}"
    openssl req -x509 -sha256 -new -nodes -key ${CA_KEY} \
        -days ${CA_EXPIRE} -out ${CA_CERT} -subj "/CN=${CA_SUBJECT}" >/dev/null || exit 1
fi

echo "====> Generating new config file ${SSL_CONFIG}"
cat >${SSL_CONFIG} <<EOM
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
EOM

if [[ -n ${SSL_DNS} || -n ${SSL_IP} ]]; then
    cat >>${SSL_CONFIG} <<EOM
subjectAltName = @alt_names
[alt_names]
EOM
    IFS=","
    dns=(${SSL_DNS})
    dns+=(${SSL_SUBJECT})
    for i in "${!dns[@]}"; do
        echo DNS.$((i + 1)) = ${dns[$i]} >>${SSL_CONFIG}
    done

    if [[ -n ${SSL_IP} ]]; then
        ip=(${SSL_IP})
        for i in "${!ip[@]}"; do
            echo IP.$((i + 1)) = ${ip[$i]} >>${SSL_CONFIG}
        done
    fi
fi

echo "====> Generating new SSL KEY ${SSL_KEY}"
openssl genrsa -out ${SSL_KEY} ${SSL_SIZE} >/dev/null || exit 1

echo "====> Generating new SSL CSR ${SSL_CSR}"
openssl req -sha256 -new -key ${SSL_KEY} -out ${SSL_CSR} \
    -subj "/CN=${SSL_SUBJECT}" -config ${SSL_CONFIG} >/dev/null || exit 1

echo "====> Generating new SSL CERT ${SSL_CERT}"
openssl x509 -sha256 -req -in ${SSL_CSR} -CA ${CA_CERT} \
    -CAkey ${CA_KEY} -CAcreateserial -out ${SSL_CERT} \
    -days ${SSL_EXPIRE} -extensions v3_req \
    -extfile ${SSL_CONFIG} >/dev/null || exit 1

echo "====> Complete"