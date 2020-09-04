import Head from 'next/head'
import styles from '../styles/Home.module.css'
import React, { Component } from 'react';


class Home extends Component {
  constructor(props){
    super(props)

    this.state = {
      password: '',
      secretKey: '',
      generatedPassword: ''
    }

    this.onChange = this.onChange.bind(this)
    this.generate = this.generate.bind(this)
  }


  onChange(e) {
    this.setState({
      [e.target.name]: e.target.value
    })
  }

  async generate(e) {
    e.preventDefault()
    const { password, secretKey } = this.state

    if (password && secretKey) {
      const { generatedPassword } = await fetch('/api/password', {
        method: 'POST',
        body: JSON.stringify({
          password,
          secretKey
        })
      }).then(res => res.json())
  
      this.setState({
        generatedPassword
      })
    }
    
  }
  
  render () {  
    return (
      <div className={styles.container}>
        <Head>
          <title>EasyPwd - there's no need to remember password anymore</title>
          <link rel="icon" href="/favicon.ico" />
          <script data-ad-client="ca-pub-2963124893727920" async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>
        </Head>

        <main className={styles.main}>
          <h1 className={styles.title}>
            EasyPwd
          </h1>

          <p className={styles.description}>
            There's no need to remember password anymore
          </p>

          <div className={styles.grid}>
            <form className={styles.card} onSubmit={this.generate}>
              <input type='text' name='password' placeholder='Password' className={styles.input} onChange={this.onChange}/>
              <input type='password' name='secretKey' placeholder='Secret Key' className={styles.input} onChange={this.onChange}/>
              <button onClick={this.generate} className={styles.btn}>Generate</button>
              {
                this.state.generatedPassword && (
                  <>
                    <br/><br/>
                    <hr/>
                    <br/>
                    <code className={styles.code}>{this.state.generatedPassword}</code>
                  </>
                )
              }
            </form>
          </div>
        </main>

        <footer className={styles.footer}>
          <a
            href="https://xianyangwong.com"
            target="_blank"
            rel="noopener noreferrer"
          >
            Powered by{' '}
            <img src="/xianyang.svg" alt="Vercel Logo" className={styles.logo} />
          </a>
        </footer>
      </div>
    )
  }
}


export default Home