package vbox

import "errors"

// DeniedError 策略明确拒绝（对应协议层 state=rejected）：沙箱无法落实规则时
// 启动前拒绝执行（fail-closed），不产生裸跑。调用方按类型识别以保持拒绝语义。
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return e.Reason }

// UnsupportedError reports a valid policy that the selected backend cannot
// enforce faithfully. It is distinct from a rule syntax error.
type UnsupportedError struct{ Reason string }

func (e *UnsupportedError) Error() string { return e.Reason }

// IsUnsupported reports whether err describes a backend capability gap.
func IsUnsupported(err error) bool {
	var target *UnsupportedError
	return errors.As(err, &target)
}
