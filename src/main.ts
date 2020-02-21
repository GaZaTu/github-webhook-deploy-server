import * as http from 'http'
import * as http2 from 'http2'
import * as Koa from 'koa'
import * as KoaRouter from 'koa-router'
import * as cors from '@koa/cors'
import * as jsonError from 'koa-json-error'
// import * as bodyparser from 'koa-bodyparser'
import * as config from 'config'
import * as crypto from 'crypto'
import { exec } from 'child_process'
import { promisify } from 'util'

const createRouter = (registerRoutes: (router: KoaRouter) => void) => {
  const router = new KoaRouter()

  registerRoutes(router)

  const middlewares = [router.routes(), router.allowedMethods()]

  return [router, middlewares] as [typeof router, typeof middlewares]
}

const createKoa = (middlewares: Koa.Middleware<any, any>[]) => {
  const koa = new Koa()

  koa.use(cors({
    origin: '*',
    allowHeaders: ['Content-Type', 'Authorization'],
  }))

  koa.use(jsonError({
    format: (err: any, obj: any) => ({
      name: err.name,
      message: err.message,
      type: err.type,
      status: err.status,
      stack: (process.env.NODE_ENV !== 'production') ? err.stack : undefined,
    }),
  }))

  // koa.use(bodyparser())

  for (const middleware of middlewares) {
    koa.use(middleware)
  }

  const callback = koa.callback()

  return [koa, callback] as [typeof koa, typeof callback]
}

const createHttpServer = (callback: (req: http.IncomingMessage | http2.Http2ServerRequest, res: http.ServerResponse | http2.Http2ServerResponse) => void) => {
  let server!: http.Server | http2.Http2SecureServer

  if (config.has('httpsConfig')) {
    const httpsConfig = Object.assign({}, config.get('httpsConfig'), { allowHTTP1: true })

    server = http2.createSecureServer(httpsConfig, callback)
  } else {
    server = http.createServer(callback)
  }

  const listen = () =>
    new Promise<void>(resolve => {
      server.listen(config.get('port'), config.get('host'), resolve)
    })

  return [server, listen] as [typeof server, typeof listen]
}

interface Payload {
  readonly repository?: {
    readonly full_name: string
  }
  readonly ref?: string
}

interface Application {
  readonly remotePath: string
  readonly localPath: string
  readonly ref: string
  readonly command: string
}

const registerRoutes = (router: KoaRouter) => {
  const applications = config.get<Application[]>('applications')
    .reduce((map, app) => { map.set(app.remotePath, app); return map; }, new Map<string, Application>())

  router.post('/handle', async ctx => {
    const algorithm = 'sha1'
    const actualSignature = ctx.headers['x-hub-signature']
    const expectedSignature = `${algorithm}=${
      crypto.createHmac(algorithm, config.get('secret'))
        .update(ctx.body)
        .digest('hex')
      }`

    const payload = JSON.parse(ctx.body) as Payload | undefined
    const application = applications.get(payload?.repository?.full_name!)

    const isValidSignature = actualSignature === expectedSignature
    const isValidRef = payload?.ref === application?.ref

    if (application && isValidSignature && isValidRef) {
      await promisify(exec)(application.command, { cwd: application.localPath })
    }
  })
}

(async () => {
  const [, middlewares] = createRouter(registerRoutes)
  const [, callback] = createKoa(middlewares)
  const [, listen] = createHttpServer(callback)

  await listen()

  console.log('listening')
})()
