<?php

namespace App\Http\Controllers;

use App\Models\Project;
use Illuminate\Http\Request;

class ProjectController extends Controller
{
    public function archive($id)
    {
        Project::find($id)->update(['archived' => true]);

        return ['ok' => true];
    }

    public function switchCompany(Request $request)
    {
        $companyId = $request->input('company_id');
        session(['company_id' => $companyId]);

        return ['ok' => true];
    }
}
