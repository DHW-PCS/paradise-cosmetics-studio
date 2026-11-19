import React, { useState, useEffect } from 'react'
import Autosuggest from 'react-autosuggest'
import { emit } from '@/scripts/event'

const domainNames = new Set(['qq.com', '163.com', 'gmail.com', 'hotmail.com'])

type Props = Omit<Autosuggest.InputProps<string>, 'onChange'> & {
  onChange(value: string): void
}

const EmailSuggestion: React.FC<Props> = (props) => {
  const [suggestions, setSuggestions] = useState<string[]>([])

  useEffect(() => {
    emit('emailDomainsSuggestion', domainNames)
  }, [])

  const handleSuggestionsFetchRequested: Autosuggest.SuggestionsFetchRequested =
    ({ value }) => {
      const segments = value.split('@')
      setSuggestions([...domainNames].map((name) => `${segments[0]}@${name}`))
    }

  const handleSuggestionsClearRequested = () => {
    setSuggestions([])
  }

  const shouldRenderSuggestions = (value: string) => {
    const isSelecting = [...domainNames].some((name) =>
      value.endsWith(`@${name}`),
    )

    return isSelecting || (value.length > 0 && !value.includes('@'))
  }

  const getSuggestionValue = (value: string) => value

  const renderSuggestion = (suggestion: string) => suggestion

  const handleChange = (_: React.FormEvent, event: Autosuggest.ChangeEvent) => {
    props.onChange(event.newValue)
  }

  const renderInputComponent = (
    props: Omit<Autosuggest.InputProps<string>, 'onChange'>,
  ) => <input {...props} className="auth-email-input" />

  return (
    <div>
      <Autosuggest
        suggestions={suggestions}
        onSuggestionsFetchRequested={handleSuggestionsFetchRequested}
        onSuggestionsClearRequested={handleSuggestionsClearRequested}
        getSuggestionValue={getSuggestionValue}
        renderSuggestion={renderSuggestion}
        shouldRenderSuggestions={shouldRenderSuggestions}
        inputProps={Object.assign({}, props, { onChange: handleChange })}
        renderInputComponent={renderInputComponent}
        theme={{
          container: 'auth-email-field',
          suggestion: 'auth-suggestion',
          suggestionsContainer: 'auth-suggestions-container',
          suggestionsList: `auth-suggestions-list ${suggestions.length ? 'show' : ''}`,
          suggestionHighlighted: 'auth-suggestion-highlighted',
        }}
      />
    </div>
  )
}

export default EmailSuggestion
