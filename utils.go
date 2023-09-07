package main

func cloneBytes(src []byte) []byte {
	res := make([]byte, len(src))
	copy(res, src)
	return res
}
