import fs, { readdir, readFileSync, existsSync, symlinkSync } from "fs";
import path, { basename, dirname } from "path";
import {Utils} from './utils'
import { ITestResult, ITestResultContainer } from "../database/models"
import moment from 'moment';
import { UploadReportEndpoint } from '../endpoints';
import axios from 'axios'
import { TestReportService } from '../services';
import DB from "../database"
import { exit } from 'process';
import { Uploader } from '../workers/upload'
import { spawn, Thread, Worker, Pool } from "threads"

const baseurl = "http://localhost:5000/api/v1"
//const baseurl = "https://report:p4ssw0rd123@reportanalyzer.alphanudel.de/api/v1"
const remote = false

const pool = Pool(() => spawn<Uploader>(new Worker('../workers/upload')))

async function main() {
  if (!remote) {
    await DB.connect()
  }

  console.log("start")
  const absolutePath = path.resolve(process.argv[2])
  console.log(absolutePath)

  let files: string[] = await new Promise<string[]>(resolve => {
    Utils.walk(absolutePath, (err, results) => {
      resolve(results)
    }, f => {
      return /testResults\.json$/.test(f)
    })
  })

  files.sort()

  let uploadedIdentifiers: string[]  = []
  if (remote) {
    const resp = await axios.get(baseurl + "/testReportIdentifiers")
    uploadedIdentifiers = resp.data
  } else {
    const results = await DB.testResultContainer.find().select({Identifier: 1}).lean().exec()
    uploadedIdentifiers = results.map((i: any) => i.Identifier)
    uploadedIdentifiers.sort()
  }
  
  const promises: Promise<any>[] = []

  for (const f of files) {
    try {
      const dir = path.dirname(f)
      if (uploadedIdentifiers.includes(basename(dir))) continue;
      console.log(basename(dir))

      const pcap = path.join(dir, 'dump.pcap')
      const keyfile = path.join(dir, 'keyfile.log')
      const results = f

      if (!existsSync(results) || !existsSync(keyfile) || !existsSync(pcap)) {
        console.error("Files missing in folder " + dir)
        continue
      }

      const pcapContent = readFileSync(pcap).toString('base64')
      const keyfileContent = readFileSync(keyfile).toString('base64')

      console.time("parseJson")
      const resultsContent: ITestResultContainer = JSON.parse(readFileSync(results, 'utf-8'))
      console.timeEnd("parseJson")

      resultsContent.Identifier = basename(dir)
      resultsContent.Date = moment(basename(dirname(dir)), "DD-MM-YY_HHmmss").toDate()
      resultsContent.ShortIdentifier = basename(dir).replace('client', 'c').replace('server', 's')
      resultsContent.ShortIdentifier = resultsContent.ShortIdentifier.slice(0, resultsContent.ShortIdentifier.length - 6)

      const uploadData: UploadReportEndpoint.IBody = {
        keylog: keyfileContent,
        pcapDump: pcapContent,
        testReport: resultsContent
      }


      if (remote) {
        console.log("Upload via remote")
        await new Promise<void>((res) => {
          axios.post(baseurl + '/uploadReport', uploadData, {
            maxContentLength: 500000000
          }).then(() => {
            console.log('Uploaded ' + resultsContent.Identifier)
            res()
          }).catch((e: Error) => {
            e.stack = null
            console.error("Upload failed " + resultsContent.Identifier, e.message)
            res()
          })
        })
      } else {

        console.time("startUpload")
        const prom = pool.queue(upload => upload(uploadData.testReport, uploadData.pcapDump, uploadData.keylog)).then(() => {
          console.log(`Uploaded ${uploadData.testReport.Identifier}`)
        })

        promises.push(prom)
        console.timeEnd("startUpload")

        // console.time("prepare")
        // const testReportService = new TestReportService(uploadData.testReport)
        // const formattedReport = testReportService.prepareTestReport()
        // console.timeEnd("prepare")
        
        // console.time("addContainer")
        // promises = promises.concat(DB.addResultContainer(formattedReport, uploadData.pcapDump, uploadData.keylog))
        // console.timeEnd("addContainer")
        // console.log(promises)
      }
    } catch(e) {
      console.error(f, e, e.stack)
    }
  }

  await Promise.all(promises)

  exit(0)
}

main()