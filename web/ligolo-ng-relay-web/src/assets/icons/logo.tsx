import { SVGProps } from "react";

interface ILogoProps extends SVGProps<SVGSVGElement> {
  size?: number
}

export const Logo = ({ size = 36, ...props }: ILogoProps) => (
  <svg
    fill="none"
    height={size}
    width={size}
    viewBox="-220 0 600.000000 380.000000"
    {...props}
  >
    <g
      transform="translate(0.000000,380.000000) scale(0.0900000,-0.0900000)"
      fill="#ad1a10"
      stroke="none"
    >
      <path d="M 1565,2732 C 1230,2145 741,1290 478,833 L 2,0 h 351 352 l 1060,1852 c 583,1018 1072,1873 1088,1900 l 27,48 h -352 l -353,-1 z" />
      <path d="M 2810,2732 C 2475,2145 1986,1290 1723,833 L 1247,0 h 351 352 l 1060,1852 c 583,1018 1072,1873 1088,1900 l 27,48 h -352 l -353,-1 z" />
    </g>
  </svg>
);
