<?php

namespace App\Http\Controllers;

use App\Models\Document;

class DocumentController extends Controller
{
    public function show(Document $document)
    {
        $this->authorize('view', $document);

        return $document;
    }

    public function destroy(Document $document)
    {
        $document->delete();

        return response()->noContent();
    }
}
