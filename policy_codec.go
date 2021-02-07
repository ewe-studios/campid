package campid

// type PolicyCodec interface {
// 	Decode(r io.Reader) (ActionPolicy, error)
// 	Encode(w io.Writer, s ActionPolicy) error
// }

// func CreatePolicyDocumentMapping() (*mapping.DocumentMapping, error) {
// 	var policyMapping = bleve.NewDocumentMapping()

// 	var textField = bleve.NewTextFieldMapping()
// 	textField.Analyzer = keyword.Name

// 	var scopeMapping = bleve.NewDocumentMapping()
// 	scopeMapping.AddFieldMappingsAt("Scope", textField)

// 	policyMapping.AddFieldMappingsAt("Id", textField)
// 	policyMapping.AddFieldMappingsAt("Name", textField)
// 	policyMapping.AddFieldMappingsAt("Permission", textField)

// 	return policyMapping, nil
// }

// func CreateLimitedPolicyDocumentMapping() (*mapping.DocumentMapping, error) {
// 	var policyMapping = bleve.NewDocumentMapping()

// 	var textField = bleve.NewTextFieldMapping()
// 	textField.Analyzer = keyword.Name

// 	policyMapping.AddFieldMappingsAt("Id", textField)
// 	policyMapping.AddFieldMappingsAt("Name", textField)

// 	return policyMapping, nil
// }

// // MsgPackPolicyCodec implements the PolicyCodec interface for using
// // the MsgPack Codec.
// type MsgPackPolicyCodec struct{}

// // Encode encodes giving session using the internal MsgPack format.
// // Returning provided data.
// func (gb *MsgPackPolicyCodec) Encode(w io.Writer, s ActionPolicy) error {
// 	if err := msgpack.NewEncoder(w).Encode(s); err != nil {
// 		return nerror.Wrap(err, "Failed to encode giving session")
// 	}
// 	return nil
// }

// // Decode decodes giving data into provided session instance.
// func (gb *MsgPackPolicyCodec) Decode(r io.Reader) (ActionPolicy, error) {
// 	var s ActionPolicy
// 	if err := msgpack.NewDecoder(r).Decode(&s); err != nil {
// 		return s, nerror.WrapOnly(err)
// 	}
// 	return s, nil
// }

// // JsonPolicyCodec implements the PolicyCodec interface for using
// // the Json Codec.
// type JsonPolicyCodec struct{}

// // Encode encodes giving session using the internal Json format.
// // Returning provided data.
// func (gb *JsonPolicyCodec) Encode(w io.Writer, s ActionPolicy) error {
// 	if err := json.NewEncoder(w).Encode(s); err != nil {
// 		return nerror.Wrap(err, "Failed to encode giving session")
// 	}
// 	return nil
// }

// // Decode decodes giving data into provided session instance.
// func (gb *JsonPolicyCodec) Decode(r io.Reader) (ActionPolicy, error) {
// 	var s ActionPolicy
// 	if err := json.NewDecoder(r).Decode(&s); err != nil {
// 		return s, nerror.WrapOnly(err)
// 	}
// 	return s, nil
// }

// // GobPolicyCodec implements the PolicyCodec interface for using
// // the gob Codec.
// type GobPolicyCodec struct{}

// // Encode encodes giving session using the internal gob format.
// // Returning provided data.
// func (gb *GobPolicyCodec) Encode(w io.Writer, s ActionPolicy) error {
// 	if err := gob.NewEncoder(w).Encode(s); err != nil {
// 		return nerror.Wrap(err, "Failed to encode giving session")
// 	}
// 	return nil
// }

// // Decode decodes giving data into provided session instance.
// func (gb *GobPolicyCodec) Decode(r io.Reader) (ActionPolicy, error) {
// 	var s ActionPolicy
// 	if err := gob.NewDecoder(r).Decode(&s); err != nil {
// 		return s, nerror.WrapOnly(err)
// 	}
// 	return s, nil
// }
