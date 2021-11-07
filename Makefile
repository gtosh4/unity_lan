
PROTO_FILES := $(find proto/ -name '*.proto')

gen/proto/go/unitylan: $(PROTO_FILES)
	buf generate
