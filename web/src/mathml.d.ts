import type { ReactNode } from "react";

type MathMLProps = {
  children?: ReactNode;
  display?: "block" | "inline";
  title?: string;
  className?: string;
  [attribute: string]: unknown;
};

declare global {
  namespace JSX {
    interface IntrinsicElements {
      math: MathMLProps;
      mrow: MathMLProps;
      mi: MathMLProps;
      mo: MathMLProps;
      mn: MathMLProps;
      msup: MathMLProps;
      msub: MathMLProps;
      mfrac: MathMLProps;
      mtext: MathMLProps;
      mtable: MathMLProps;
      mtr: MathMLProps;
      mtd: MathMLProps;
    }
  }
}

export {};
