declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: any;
  }
  interface Element extends Record<string, any> {}
}

declare namespace React {
  export type ReactNode = any;
  export type CSSProperties = Record<string, any>;
  export type FC<P = {}> = (props: P) => any;
  export type FormEvent<T = any> = {
    preventDefault: () => void;
    stopPropagation: () => void;
    target: T;
  };
  export type ChangeEvent<T = any> = {
    target: T;
  };
  export type MouseEvent<T = any> = {
    preventDefault: () => void;
    stopPropagation: () => void;
    target: T;
  };
  export function useState<T>(initialState: T | (() => T)): [T, (newState: T | ((prevState: T) => T)) => void];
  export function useEffect(effect: () => void | (() => void), deps?: readonly any[]): void;
  export function useCallback<T extends (...args: any[]) => any>(callback: T, deps: readonly any[]): T;
  export function useMemo<T>(factory: () => T, deps: readonly any[] | undefined): T;
  export function useRef<T>(initialValue?: T): { current: T };
  export function createContext<T>(defaultValue: T): any;
  export function useContext<T>(context: any): T;
}

declare module 'react' {
  export = React;
}

declare module 'react/jsx-runtime' {
  export const jsx: any;
  export const jsxs: any;
  export const Fragment: any;
}

declare module 'react-dom/client' {
  export interface Root {
    render(children: any): void;
    unmount(): void;
  }
  export function createRoot(container: any): Root;
}

declare module 'react-router-dom' {
  export const BrowserRouter: any;
  export const Routes: any;
  export const Route: any;
  export const Link: any;
  export const NavLink: any;
  export const Navigate: any;
  export function useNavigate(): (to: string | number, options?: any) => void;
  export function useLocation(): { pathname: string; search: string; hash: string; state: any };
  export function useParams<T extends Record<string, string | undefined>>(): T;
}
