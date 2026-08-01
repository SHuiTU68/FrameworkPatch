// pkijs 在 keybox.ts 中以 any 形式动态调用，保留 ambient 声明避免 strict 报错。
// kernelsu-alt v3+ 已自带类型（node_modules/kernelsu-alt/dist/index.d.ts），无需在此声明。
declare module 'pkijs';
