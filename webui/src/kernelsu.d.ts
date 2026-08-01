// kernelsu-alt 桥接类型声明（该包未附带类型，此处补全以便 strict 编译）
declare module 'kernelsu-alt' {
  export interface ExecResult {
    errno: number;
    stdout: string;
    stderr: string;
  }

  export interface PackageInfo {
    name: string;
    label: string;
    versionName: string;
    versionCode: number;
    system: boolean;
    enabled: boolean;
    firstInstallTime: number;
    lastUpdateTime: number;
  }

  export function exec(cmd: string): Promise<ExecResult>;
  export function spawn(cmd: string): Promise<ExecResult>;
  export function toast(message: string): void;
  export function fullScreen(enable: boolean): void;
  export function listPackages(): Promise<string[]>;
  export function getPackagesInfo(packages: string[]): Promise<PackageInfo[]>;

  const _default: {
    exec: typeof exec;
    spawn: typeof spawn;
    toast: typeof toast;
    fullScreen: typeof fullScreen;
    listPackages: typeof listPackages;
    getPackagesInfo: typeof getPackagesInfo;
  };
  export default _default;
}

// pkijs 未附带类型，证书解析在 try/catch 中调用，故声明为 any
declare module 'pkijs';
