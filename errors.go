package vbox

// DeniedError 策略明确拒绝（对应协议层 state=rejected）：沙箱无法落实规则时
// 启动前拒绝执行（fail-closed），不产生裸跑。调用方按类型识别以保持拒绝语义。
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return e.Reason }
