//go:build windows
// +build windows

package wincrypt

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"syscall"
	"unsafe"

	"github.com/rclone/rclone/fs"
	"golang.org/x/sys/windows"
)

var (
	ncrypt                                   = syscall.NewLazyDLL("ncrypt.dll")
	crypt32                                  = syscall.NewLazyDLL("crypt32.dll")
	cryptui                                  = syscall.NewLazyDLL("cryptui.dll")
	procCryptUIDlgSelectCertificateFromStore = cryptui.NewProc("CryptUIDlgSelectCertificateFromStore")
	procCryptAcquireCertificatePrivateKey    = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procNCryptGetProperty                    = ncrypt.NewProc("NCryptGetProperty")
	procNCryptSignHash                       = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject                     = ncrypt.NewProc("NCryptFreeObject")
)

func convertToWindowsString(s string) *uint16 {
	res, _ := windows.UTF16PtrFromString(s)
	return res
}

const (
	NCRYPT_KEY_USAGE_PROPERTY       = "Key Usage"
	NCRYPT_ALGORITHM_GROUP_PROPERTY = "Algorithm Group"
	NCRYPT_ECDH_ALGORITHM_GROUP     = "ECDH"
	NCRYPT_RSA_ALGORITHM_GROUP      = "RSA"
	NCRYPT_ECDSA_ALGORITHM_GROUP    = "ECDSA"
	BCRYPT_SHA1_ALGORITHM           = "SHA1"
	BCRYPT_SHA256_ALGORITHM         = "SHA256"
	BCRYPT_SHA384_ALGORITHM         = "SHA384"
	BCRYPT_SHA512_ALGORITHM         = "SHA512"
	BCRYPT_MD4_ALGORITHM            = "MD4"
	BCRYPT_MD5_ALGORITHM            = "MD5"

	CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000
	NCRYPT_ALLOW_ALL_USAGES            = 0x00ffffff
	NCRYPT_ALLOW_DECRYPT_FLAG          = 0x00000001
	NCRYPT_ALLOW_SIGNING_FLAG          = 0x00000002
	NCRYPT_ALLOW_KEY_AGREEMENT_FLAG    = 0x00000004
	BCRYPT_PAD_PKCS1                   = 0x00000002
	BCRYPT_PAD_PSS                     = 0x00000008
	ERROR_SUCCESS                      = 0x0
)

const (
	KEY_TYPE_RSA = 0
	KEY_TYPE_ECC = 1
)

type BCRYPT_PKCS1_PADDING_INFO struct {
	pszAlgId *uint16
}

type BCRYPT_PSS_PADDING_INFO struct {
	pszAlgId *uint16
	cbSalt   uint32
}

type WINCRYPT struct {
	crypto.Signer
	io.Closer
	cert    tls.Certificate
	priv    syscall.Handle
	keyType int
}

func isKeySuitableForSigning(prov syscall.Handle, keyType int) (bool, error) {
	var keyUsage uint32
	var keyUsageSize uint32 = 4
	status, err := NCryptGetProperty(prov, NCRYPT_KEY_USAGE_PROPERTY, uintptr(unsafe.Pointer(&keyUsage)), keyUsageSize, &keyUsageSize, 0)
	if status != ERROR_SUCCESS || err != syscall.Errno(0) {
		err = fmt.Errorf("Failed to get Key Usage information: status = 0x%x, err = %v", status, err)
		return false, err
	}
	switch {
	case keyUsage == NCRYPT_ALLOW_ALL_USAGES:
		fs.Debugf(NCRYPT_KEY_USAGE_PROPERTY, "All usage flag set")
		return true, nil
	case keyUsage&NCRYPT_ALLOW_SIGNING_FLAG != 0:
		fs.Debugf(NCRYPT_KEY_USAGE_PROPERTY, "Signing usage flag set")
		return true, nil
	case (keyUsage&NCRYPT_ALLOW_KEY_AGREEMENT_FLAG != 0) && (keyType == KEY_TYPE_ECC):
		fs.Debugf(NCRYPT_KEY_USAGE_PROPERTY, "Allow ECC key with key agreement usage flag set")
		return true, nil
	default:
		return false, fmt.Errorf("Provided key is not suitable for signing purpose")
	}
}

func LoadWincrypt() (crypt *WINCRYPT, err error) {
	crypt = new(WINCRYPT)
	ctx, err := SelectCertificateFromUserStore()
	if err != nil {
		return nil, err
	}
	defer syscall.CertFreeCertificateContext(ctx)
	buf := make([]byte, ctx.Length)
	buf1 := (*[1 << 20]byte)(unsafe.Pointer(ctx.EncodedCert))[:]
	copy(buf, buf1)
	cert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, err
	}
	fs.Debugf("Certificate Subject", cert.Subject.String())
	crypt.cert = tls.Certificate{
		PrivateKey:  crypt,
		Leaf:        cert,
		Certificate: [][]byte{cert.Raw},
	}
	var keyFlags uint32
	var callerFree bool
	status, err := CryptAcquireCertificatePrivateKey(ctx, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, &(crypt.priv), &keyFlags, &callerFree)
	if status != 1 {
		return nil, err
	}
	crypt.keyType, err = NCryptGetPrivateKeyType(crypt.priv)
	if err != nil {
		crypt.Close()
		return nil, err
	}
	v, err := isKeySuitableForSigning(crypt.priv, crypt.keyType)
	if !v || err != nil {
		crypt.Close()
		return nil, err
	}
	if crypt.keyType == KEY_TYPE_ECC {
		crypt.cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{
			tls.ECDSAWithSHA1,
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.ECDSAWithP521AndSHA512,
		}
	} else {
		crypt.cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{
			tls.PKCS1WithSHA1,
			tls.PKCS1WithSHA256,
			tls.PKCS1WithSHA384,
			tls.PKCS1WithSHA512,
			tls.PSSWithSHA256,
			tls.PSSWithSHA384,
			tls.PSSWithSHA512,
		}
	}
	return crypt, nil
}

func (w *WINCRYPT) Public() crypto.PublicKey {
	return w.cert.Leaf.PublicKey
}

func (w *WINCRYPT) TLSCertificate() tls.Certificate {
	return w.cert
}

func goHashToNCryptHash(h crypto.Hash) (alg *uint16, err error) {
	err = nil
	switch h {
	case crypto.MD4:
		alg = convertToWindowsString(BCRYPT_MD4_ALGORITHM)
	case crypto.MD5:
		alg = convertToWindowsString(BCRYPT_MD5_ALGORITHM)
	case crypto.SHA1:
		alg = convertToWindowsString(BCRYPT_SHA1_ALGORITHM)
	case crypto.SHA256:
		alg = convertToWindowsString(BCRYPT_SHA256_ALGORITHM)
	case crypto.SHA384:
		alg = convertToWindowsString(BCRYPT_SHA384_ALGORITHM)
	case crypto.SHA512:
		alg = convertToWindowsString(BCRYPT_SHA512_ALGORITHM)
	default:
		err = fmt.Errorf("no suitable hash algorithm found for %v", h)
	}
	return alg, err
}

func (w *WINCRYPT) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var err error = nil
	var sign []byte
	var paddingInfo uintptr
	var signFlags uint32
	var status uint32
	var signingType string = "ECDSA"
	if w.keyType == KEY_TYPE_RSA {
		pss, ok := opts.(*rsa.PSSOptions)

		alg, err := goHashToNCryptHash(opts.HashFunc())
		if err != nil {
			return []byte{}, err
		}
		if ok {
			signingType = "RSA PSS"
			pssPad := BCRYPT_PSS_PADDING_INFO{}
			pssPad.pszAlgId = alg
			var cbSalt uint32
			if pss.SaltLength == rsa.PSSSaltLengthEqualsHash || pss.SaltLength == rsa.PSSSaltLengthAuto {
				cbSalt = uint32(opts.HashFunc().Size())
			} else {
				cbSalt = uint32(pss.SaltLength)
			}
			pssPad.cbSalt = cbSalt
			signFlags = BCRYPT_PAD_PSS
			paddingInfo = uintptr(unsafe.Pointer(&pssPad))
		} else {
			signingType = "RSA PKCS1"
			pkcs1Pad := BCRYPT_PKCS1_PADDING_INFO{}
			pkcs1Pad.pszAlgId = alg
			signFlags = BCRYPT_PAD_PKCS1
			paddingInfo = uintptr(unsafe.Pointer(&pkcs1Pad))
		}
	} else if w.keyType != KEY_TYPE_ECC {
		err = fmt.Errorf("unsupported private key type")
	}
	if err != nil {
		return []byte{}, err
	}
	sig, status, _ := NCryptSignHash(w.priv, paddingInfo, digest, (uint32)(len(digest)), signFlags)
	if status != ERROR_SUCCESS {
		err = fmt.Errorf("%s Signing failed, status = 0x%x", signingType, status)
		return []byte{}, err
	}
	if w.keyType == KEY_TYPE_ECC {
		sign, err = ECDSAConvertIEEEP1363ToASN1(sig)
		if err != nil {
			return []byte{}, err
		}
	} else {
		sign = sig
	}
	fs.Debugf(nil, "%s Signed successfully", signingType)
	return sign, err
}

func (w *WINCRYPT) Close() error {
	status := NCryptFreeObject(w.priv)
	if status != ERROR_SUCCESS {
		return fmt.Errorf("NCryptFreeObject failed, status = %x", status)
	}
	return nil
}

func SelectCertificateFromUserStore() (ctx *syscall.CertContext, err error) {
	storeName, err := windows.UTF16PtrFromString("My")
	if err != nil {
		return nil, err
	}
	store, err := syscall.CertOpenSystemStore(syscall.Handle(0), storeName)
	if err != nil {
		return nil, err
	}
	defer syscall.CertCloseStore(store, 0)
	HCtx, _, err := procCryptUIDlgSelectCertificateFromStore.Call((uintptr)(store), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	if HCtx == 0x0 || err != syscall.Errno(0) {
		return nil, err
	}
	// It's valid since PCCERT_CONTEXT objects lives until CertFreeCertificateContext is called
	ctx = (*syscall.CertContext)(unsafe.Pointer(HCtx))
	err = nil
	return
}

func NCryptGetProperty(prov syscall.Handle, prop string, pbOut uintptr, cbOut uint32, pcbOut *uint32, dwFlags uint32) (status uint32, err error) {
	wstr, _ := windows.UTF16PtrFromString(prop)
	sta, _, err := procNCryptGetProperty.Call(uintptr(prov), uintptr(unsafe.Pointer(wstr)), pbOut, uintptr(cbOut), uintptr(unsafe.Pointer(pcbOut)), uintptr(dwFlags))
	status = uint32(sta)
	return
}

func CryptAcquireCertificatePrivateKey(ctx *syscall.CertContext, dwFlags uint32, prov *syscall.Handle, pdwKeySpec *uint32, callerFree *bool) (status uint32, err error) {
	var callerFree_ uint32 = 0
	sta, _, err := procCryptAcquireCertificatePrivateKey.Call((uintptr)(unsafe.Pointer(ctx)), uintptr(dwFlags), 0x0, (uintptr)(unsafe.Pointer(prov)), (uintptr)(unsafe.Pointer(pdwKeySpec)), (uintptr)(unsafe.Pointer(&callerFree_)))
	*callerFree = (callerFree_ == 1)
	status = uint32(sta)
	return
}

func NCryptFreeObject(obj syscall.Handle) (status uint32) {
	sta, _, _ := procNCryptFreeObject.Call(uintptr(obj))
	status = uint32(sta)
	return
}

func NCryptSignHash(prov syscall.Handle, paddingInfo uintptr, hash []byte, cbHash uint32, dwFlags uint32) (sig []byte, status uint32, err error) {
	var sigSize uint32
	sta, _, err := procNCryptSignHash.Call(uintptr(prov), 0x0, (uintptr)(unsafe.Pointer(&hash[0])), uintptr(cbHash), 0x0, 0x0, (uintptr)(unsafe.Pointer(&sigSize)), uintptr(dwFlags))
	if sta != ERROR_SUCCESS || err != syscall.Errno(0) {
		err = fmt.Errorf("Failed to get signature size: status = %x, err = %v\n", sta, err)
		return []byte{}, 0x0, err
	}
	var signature = make([]byte, sigSize)
	sta, _, err = procNCryptSignHash.Call(uintptr(prov), paddingInfo, (uintptr)(unsafe.Pointer(&hash[0])), uintptr(cbHash), uintptr(unsafe.Pointer(&signature[0])), uintptr(sigSize), (uintptr)(unsafe.Pointer(&sigSize)), uintptr(dwFlags))
	status = uint32(sta)
	sig = signature
	return
}

func ECDSAConvertIEEEP1363ToASN1(src []byte) (dst []byte, err error) {
	// R and S
	var sigs = [2]*big.Int{new(big.Int), new(big.Int)}
	sigs[0].SetBytes(src[:len(src)/2])
	sigs[1].SetBytes(src[len(src)/2:])
	dst, err = asn1.Marshal(sigs[:])
	if err != nil {
		return []byte{}, err
	}
	return
}

func NCryptGetPrivateKeyType(prov syscall.Handle) (keyType int, err error) {
	var propertySize uint32
	status, err := NCryptGetProperty(prov, NCRYPT_ALGORITHM_GROUP_PROPERTY, 0x0, 0x0, &propertySize, 0)
	if status != ERROR_SUCCESS || err != syscall.Errno(0) {
		err = fmt.Errorf("failed to query algorithm group size, status = %x, err = %v", status, err)
		return -1, err
	}
	var alg = make([]uint16, propertySize/2)
	status, err = NCryptGetProperty(prov, NCRYPT_ALGORITHM_GROUP_PROPERTY, uintptr(unsafe.Pointer(&alg[0])), propertySize, &propertySize, 0)
	if status != ERROR_SUCCESS || err != syscall.Errno(0) {
		err = fmt.Errorf("failed to query algorithm group, status = %x, err = %v", status, err)
		return -1, err
	}
	str := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&alg[0])))
	fs.Debugf("Algorithm Group", str)
	err = nil
	if str == NCRYPT_ECDH_ALGORITHM_GROUP || str == NCRYPT_ECDSA_ALGORITHM_GROUP {
		keyType = KEY_TYPE_ECC
	} else if str == NCRYPT_RSA_ALGORITHM_GROUP {
		keyType = KEY_TYPE_RSA
	} else {
		return -1, fmt.Errorf("unsupported private key algorithm group: %v", str)
	}
	return
}
