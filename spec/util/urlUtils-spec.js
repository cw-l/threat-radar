const { constructSheetUrl, getDocumentOrSheetId, getSheetName } = require('../../src/util/urlUtils')
const queryParams = require('../../src/util/queryParamProcessor')

jest.mock('../../src/util/queryParamProcessor')

function setSearch(query) {
  window.history.replaceState({}, '', query.startsWith('?') ? query : `?${query}`)
}

describe('Url Utils', () => {
  it('should construct the sheet url', () => {
    queryParams.mockReturnValue({ documentId: 'documentId' })
    setSearch('?sheet=radar')
    const sheetUrl = constructSheetUrl('radar')

    expect(sheetUrl).toStrictEqual('https://thoughtworks.com/radar?documentId=documentId&sheetName=radar')
    expect(queryParams).toHaveBeenCalledTimes(1)
  })

  it('should construct the sheet url if sheetId is used', () => {
    queryParams.mockReturnValue({ sheetId: 'sheetId' })
    setSearch('?sheet=radar')
    const sheetUrl = constructSheetUrl('radar')

    expect(sheetUrl).toStrictEqual('https://thoughtworks.com/radar?sheetId=sheetId&sheetName=radar')
    expect(queryParams).toHaveBeenCalledTimes(1)
  })

  it('should prioritize documentId before legacy sheetId', () => {
    queryParams.mockReturnValue({ documentId: 'documentId', sheetId: 'sheetId' })
    setSearch('?documentId=documentId&sheetId=sheetId')

    const id = getDocumentOrSheetId()

    expect(id).toEqual('documentId')
  })

  it('supports documentId', () => {
    queryParams.mockReturnValue({ documentId: 'documentId' })
    setSearch('?documentId=documentId')

    const id = getDocumentOrSheetId()

    expect(id).toEqual('documentId')
  })

  it('supports sheetId', () => {
    queryParams.mockReturnValue({ sheetId: 'sheetId' })
    setSearch('?sheetId=sheetId')

    const id = getDocumentOrSheetId()

    expect(id).toEqual('sheetId')
  })

  it('supports sheetName', () => {
    queryParams.mockReturnValue({ sheetName: 'sheetName' })
    setSearch('?sheetName=sheetName')

    const sheetName = getSheetName()

    expect(sheetName).toEqual('sheetName')
  })
})
