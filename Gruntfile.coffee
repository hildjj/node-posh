module.exports = (grunt) ->

  # Load Grunt tasks declared in the package.json file
  require("jit-grunt") grunt
  grunt.initConfig
    pkg: grunt.file.readJSON("package.json")
    clean:
      all: [
        "coverage"
        "doc"
        "lib"
        "man"
      ]
      coverage: ["coverage"]
      doc: ["doc"]
      lib: ["lib"]
      man: ["man"]

    coffee:
      compile:
        expand: true
        flatten: true
        cwd: "src"
        src: ["*.coffee"]
        dest: "lib/"
        ext: ".js"

    watch:
      all:
        files: [
          "src/*.coffee"
        ]
        tasks: [
          "coffee"
        ]
        options:
          livereload: true

    release:
      options:
        tagName: "v<%= version %>" #default: '<%= version %>'

  grunt.registerTask "default", ["coffee"]
