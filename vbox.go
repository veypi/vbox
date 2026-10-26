// Package vbox 是原生子进程沙箱库：规则模型 + 纯判定 + OS 落地（Seatbelt /
// bubblewrap / 受限令牌 + ACL）+ 进程生命周期。
//
// 它只做三件事：
//
//   - 规则模型：FS 与 Net 各一张有序表，按 level + 原表序求值：高 level 优先，
//     同 level 首命中生效。行首可用 ! 增加 level，随后是效果前缀：文件域
//     ro:/rw:/deny:，网络域 allow:/deny:（host:port）。Class 只用于调用方拼接，
//     不推导 level，也不参与判定。
//   - 判定：纯函数匹配（MatchPath / Match / MatchNoFollow / NetRuleSet.Resolve），
//     不访问宿主文件系统，也不读配置。
//   - 落地：把编译好的快照交给内核机制执行；当前平台无法表达的规则在启动前拒绝
//     （fail-closed），绝不静默降级为裸跑。RunProcess 是唯一进程入口。
//
// 配置解析、默认规则源、会话授权、grant 生命周期与审批策略都属调用方（宿主集成层）；
// vbox 每次调用接收一份编译好的快照，不维护授权状态。Windows 侧仅为拒绝 ACE 的
// 幂等对账保留一份状态文件（默认 `{UserConfigDir}/vbox/sandbox/deny_acl_state.json`，
// 可用 Manager.SetStateDir 改）。
package vbox

// Effect 规则行效果。
type Effect uint8

const (
	EffDeny Effect = iota // 读写双拒
	EffRO                 // 读放写拒
	EffRW                 // 读写
)

func (e Effect) String() string {
	switch e {
	case EffDeny:
		return "deny"
	case EffRO:
		return "ro"
	case EffRW:
		return "rw"
	}
	return ""
}

// ParseEffect 解析效果词（deny/ro/rw），非法返回 ok=false。
func ParseEffect(s string) (Effect, bool) {
	switch s {
	case "deny":
		return EffDeny, true
	case "ro":
		return EffRO, true
	case "rw":
		return EffRW, true
	}
	return EffDeny, false
}

// Class 规则行类别——仅参与调用方的行序拼接（§9.10：temp → cfg/permanent →
// builtin deny → 便利根），判定时不看。
type Class uint8

const (
	ClassTemp        Class = iota // session grant（构建时插表头）
	ClassCfg                      // cfg / permanent
	ClassBuiltin                  // 出厂内建（deny 表）
	ClassConvenience              // 便利根（workspace / 会话目录等）
)

func (c Class) String() string {
	switch c {
	case ClassTemp:
		return "temp"
	case ClassCfg:
		return "cfg"
	case ClassBuiltin:
		return "builtin"
	case ClassConvenience:
		return "convenience"
	}
	return ""
}

// Rule 规则行。Pattern：段内 *（任意非分隔符字符）、跨层 **（零或多段）、
// ?（单字符）；裸路径（无通配符）覆盖子树。Class 判定时不看。
type Rule struct {
	Pattern string
	Effect  Effect
	Class   Class
	Level   uint8 // 高 level 优先；同 level 保持原表序，Class 不推导 Level
	// Resolve 可选：行命中时由回调按本次「路径 + 操作」现算效果，把「随目标
	// 数量增长的一次性枚举行」换成「一行 + 按需判定」（如云 /skills/{id} 的
	// 可见性：只查当前这一个 id，不枚举全库）。Handled=false = 回调不表态，
	// 落回 Effect（静态部分仍可读，诊断/表渲染不受影响）。行序语义不变：前面
	// 的行仍先命中、且命中本行时不再查后续行。
	//
	// 仅进程内匹配（Match/MatchPath/MatchNoFollow）调用回调；OS 级沙箱计划
	// 只认静态 Effect，带 Resolve 的行交给计划生成会被显式拒绝
	//（validateProcessPolicy）——动态判定无法下推到 seatbelt/bwrap/ACL。
	Resolve func(path string, op FileOp) Resolution
}

// Resolution 是动态行回调（Rule.Resolve）的判定结果。
type Resolution struct {
	// Effect 生效效果。
	Effect Effect
	// Reason 可选：给调用方的说明（如拒绝原因）。判定不看它，只用于报错/
	// 日志——静态行的说明由调用方自建，动态行的情形只有回调知道（例如
	// 「公开包是发布物，不可写且 grant 不可授」与「本人私有包，写需 grant」
	// 的区别）。
	Reason string
	// Handled false = 回调不表态，落回 Rule.Effect。
	Handled bool
}

// FileOp 文件操作类别。
type FileOp uint8

const (
	OpRead  FileOp = iota
	OpWrite        // 含创建/修改/删除/重命名/追加——unlink/rename 判定走 MatchNoFollow
)

// Decision 判定结果。
type Decision struct {
	Allow   bool   // 本操作是否放行
	Matched int    // 命中行序号（0 起）；-1 = 未命中（兜底生效）
	Effect  Effect // 生效效果（命中行效果或兜底）
	Level   uint8  // 命中行 level；兜底为 0
	// Reason 动态行（Rule.Resolve）或快照错误给出的说明（拒绝原因等）；
	// 普通静态命中行与兜底判定的 Reason 为空，调用方自建文案。
	Reason string
}

// FSRuleSet 文件规则集：高 level 优先，同 level 按原表序首命中。
type FSRuleSet struct {
	Rules        []Rule // 原表序在同 level 内保留；Class 不改变优先级
	DefaultWrite Effect // 未命中写兜底（EffDeny | EffRW = fs_policy）；读默认开放
	// Err 是快照来源的配置错误。非 nil 时读写都 fail-closed，且原生进程
	// 必须在任何 OS 规则落地前拒绝启动；不能用空规则代替这个状态。
	Err error
}

// NewFSRuleSet 构造规则集并对每行模式做 CanonicalPattern 归一（符号链接前缀
// 展开）。直接字面构造结构体时模式必须自行保证 canonical——查询路径在 Match
// 入口被 canonical 化，模式若不是 canonical，在 macOS /home（firmlink）、/tmp
// 等 symlink 前缀下两侧错位（规则形同虚设）。grant/cfg 来源的行经
// CompileFSRule 编译已含此归一；程序化构造的表请用本函数。
func NewFSRuleSet(rules []Rule, defaultWrite Effect) FSRuleSet {
	out := FSRuleSet{Rules: make([]Rule, len(rules)), DefaultWrite: defaultWrite}
	for i, r := range rules {
		r.Pattern = CanonicalPattern(r.Pattern)
		out.Rules[i] = r
	}
	return out
}

// Match 判定 canonical 化后的 path 上 op 是否放行（跟随末段符号链接——
// open/connect 语义）。
func (s FSRuleSet) Match(path string, op FileOp) Decision {
	return s.MatchPath(Canonical(path), op)
}

// MatchNoFollow 是 unlink/rename 语义的判定入口：末段符号链接不跟随（rm/mv
// 作用于链接本身，不触达目标），父链展开、规则表判定不变。rm/mv 类操作必须
// 走此入口——否则可写根内的外向链接会被无关目标路径的策略拒掉
// （2026-09-22 实测 .venv 删除被阻的修复，迁移不得丢）。
func (s FSRuleSet) MatchNoFollow(path string, op FileOp) Decision {
	return s.MatchPath(CanonicalNoFollow(path), op)
}

// MatchPath evaluates an already normalized path without consulting the host filesystem.
func (s FSRuleSet) MatchPath(cpath string, op FileOp) Decision {
	if s.Err != nil {
		return Decision{Allow: false, Matched: -1, Effect: EffDeny, Reason: s.Err.Error()}
	}
	best := -1
	var bestLevel uint8
	for i, r := range s.Rules {
		if best >= 0 && r.Level <= bestLevel {
			continue
		}
		if !MatchPattern(r.Pattern, cpath) {
			continue
		}
		best, bestLevel = i, r.Level
	}
	if best >= 0 {
		r := s.Rules[best]
		eff := r.Effect
		reason := ""
		if r.Resolve != nil {
			if res := r.Resolve(cpath, op); res.Handled {
				eff, reason = res.Effect, res.Reason
			}
		}
		return Decision{Allow: effectAllows(eff, op), Matched: best, Effect: eff, Level: r.Level, Reason: reason}
	}
	// 未命中：读默认开放；写走 DefaultWrite 兜底（EffDeny|EffRW）。
	if op == OpRead {
		return Decision{Allow: true, Matched: -1, Effect: EffRO}
	}
	return Decision{Allow: s.DefaultWrite == EffRW, Matched: -1, Effect: s.DefaultWrite}
}

func effectAllows(e Effect, op FileOp) bool {
	switch e {
	case EffRW:
		return true
	case EffRO:
		return op == OpRead
	default: // EffDeny
		return false
	}
}

// Resolve 返回路径的表判定（诊断/ explain 用）：命中行序号与效果。
func (s FSRuleSet) Resolve(path string) Decision {
	return s.MatchPath(Canonical(path), OpRead)
}
