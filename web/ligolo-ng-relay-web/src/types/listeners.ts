export type LigoloListeners = Listener[]

export interface Listener {
    ListenerID: number
    Agent: string
    AgentID: number
    RemoteAddr: string
    SessionID: string
    Network: string
    ListenerAddr: string
    RedirectAddr: string
    Online: boolean
}
