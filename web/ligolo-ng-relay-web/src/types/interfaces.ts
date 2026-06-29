export type LigoloInterfaces = Record<string, Interface>

export interface Interface {
    Routes: Route[]
    Active: boolean
}

export interface Route {
    Destination: string
    Active: boolean
}
