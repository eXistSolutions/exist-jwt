/**
 * build, watch and deploy tasks for the library XAR package
 */
import { src, dest, watch, series, parallel, lastRun } from 'gulp'
import { createClient, readOptionsFromEnv } from '@existdb/gulp-exist'
import replace from '@existdb/gulp-replace-tmpl'
import zip from 'gulp-zip'
import rename from 'gulp-rename'
import del from 'delete'

import pkg from './package.json' with { type: 'json' }

// read metadata from package.json and .existdb.json
const { xar, version, license } = pkg

// .tmpl replacements to include 
// first value wins
const replacements = [xar, {version, license}]

const defaultOptions = { basic_auth: { user: "admin", pass: "" } }
const connectionOptions = Object.assign(defaultOptions, readOptionsFromEnv())
const existClient = createClient(connectionOptions);

const folder = {
    dist: 'dist',
    build: 'build',
    src: 'src'
}

// construct the current xar name from available data
const xarFilename = `${xar.target}-${version}.xar`
const packageName = xar.namespace

/**
 * Use the `delete` module directly, instead of using gulp-rimraf
 */
function clean (cb) {
    del([folder.build, folder.dist], cb);
}

/**
 * replace placeholders 
 * in src/repo.xml.tmpl and 
 * output to build/repo.xml
 */
function templates () {
  return src('src/*.tmpl')
    .pipe(replace(replacements, { prefix: "package" }))
    .pipe(rename(path => { path.extname = "" }))
    .pipe(dest('build/'))
}

function watchTemplates () {
    watch('src/*.tmpl', series(templates))
}

const staticFiles = [
    "src/examples/*",
    "src/content/*",
    "src/test/*.*",
    "src/icon.svg"
]

/**
 * copy html templates, XSL stylesheet, XMLs and XQueries to 'build'
 */
function copyStatic () {
    return src(staticFiles, {base: folder.src}).pipe(dest(folder.build))
}

function watchStatic () {
    watch(staticFiles, series(copyStatic));
}

/**
 * since this is a pure library package uploading
 * the library itself will not update the compiled
 * version in the cache.
 * This is why the xar will be installed instead
 */
function watchBuild () {
    watch('build/**/*', series(xar, installXar))
}

/**
 * create XAR package in repo root
 */
function createXar () {
    return src('build/**/*', {base: folder.build, encoding: false})
        .pipe(zip(xarFilename))
        .pipe(dest(folder.dist))
}

/**
 * upload and install the latest built XAR
 */
function installXar () {
    return src(xarFilename, {cwd: folder.dist, encoding: false})
        .pipe(existClient.install())
}

// composed tasks
const build = series(
    clean,
    templates,
    copyStatic,
    createXar
)
const watchAll = parallel(
    watchStatic,
    watchTemplates,
    watchBuild
)

const install = series(build, installXar)

export {
  clean,
  templates,
  watchTemplates as "watch:tmpl",
  copyStatic,
  watchStatic as "watch:static",
  build,
  watchAll as watch,
  install
}

// main task for day to day development
export default series(build, installXar, watchAll)
